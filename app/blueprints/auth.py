"""Authentication blueprint: register, login (with optional 2FA) and logout."""

from __future__ import annotations

import hmac
import re
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .. import telegram as tg
from ..extensions import db
from ..models import AuditLog, LoginRequest, LoginRequestStatus, Role, User
from ..security import (
    PENDING_2FA_KEY,
    current_user,
    hash_password,
    login_user,
    logout_user,
    verify_password,
    verify_totp,
)

auth_bp = Blueprint("auth", __name__)

# Session key marking a login waiting for Telegram approval (the request id).
PENDING_TG_KEY = "pending_tg_login_id"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,80}$")


def _safe_next(target: str | None) -> str:
    """Return a same-site redirect target, defaulting to the dashboard.

    Only relative paths are accepted to prevent open-redirect attacks.
    """
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard.home")


def _record(action: str, user_id: int | None = None, detail: str | None = None) -> None:
    """Append an entry to the audit log (best-effort)."""
    db.session.add(AuditLog(user_id=user_id, action=action, detail=detail))
    db.session.commit()


def _notify_signin(user: User) -> None:
    """Best-effort Telegram security notice on a successful sign-in."""
    app_name = current_app.config.get("APP_NAME", "Dashboard")
    tg.notify(
        user,
        f"🔓 New sign-in to <b>{app_name}</b>.\n"
        "If this wasn't you, change your password right away.",
    )


def _finish_login(user: User, next_target: str | None):
    """Complete a successful single-factor login."""
    login_user(user)
    _record("login", user.id)
    _notify_signin(user)
    flash(f"Welcome back, {user.name}.", "success")
    return redirect(_safe_next(next_target))


def _start_telegram_login(user: User, next_target: str | None):
    """Create a pending sign-in request and prompt the user's Telegram."""
    ttl = int(current_app.config.get("LOGIN_REQUEST_TTL", 300))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    req = LoginRequest(
        user_id=user.id,
        token=tg.gen_request_token(),
        code=tg.gen_code(),
        status=LoginRequestStatus.PENDING,
        ip=request.remote_addr,
        user_agent=(request.headers.get("User-Agent") or "")[:255],
        created_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    db.session.add(req)
    db.session.commit()

    app_name = current_app.config.get("APP_NAME", "Dashboard")
    tg.send_message(
        user.telegram_id,
        f"🔐 <b>Sign-in request</b> for {app_name}\n"
        f"IP: {req.ip or 'unknown'}\n\n"
        "Approve this sign-in with the buttons below, "
        f"or type this code on the page:\n<b>{req.code}</b>",
        reply_markup=tg.login_keyboard(req.token),
    )

    # Drop any half-finished state, then remember which request we're waiting on.
    session.clear()
    session[PENDING_TG_KEY] = req.id
    if next_target:
        session["pending_next"] = next_target
    return redirect(url_for("auth.telegram_confirm"))


def _tg_redirect(url: str):
    """Redirect that works for both HTMX polls (HX-Redirect) and plain GETs."""
    if request.headers.get("HX-Request") == "true":
        resp = current_app.make_response("")
        resp.headers["HX-Redirect"] = url
        return resp
    return redirect(url)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Create a new account, then send the user to login."""
    if current_user() is not None:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        errors = []
        if not _EMAIL_RE.match(email):
            errors.append("Please enter a valid email address.")
        if not _USERNAME_RE.match(username):
            errors.append(
                "Username must be 3-80 characters: letters, digits, '.', '_' or '-'."
            )
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if password != confirm:
            errors.append("Passwords do not match.")

        # Uniqueness checks (parameterised by the ORM, never string-built SQL).
        if not errors:
            exists = db.session.scalar(
                sa.select(User).where(
                    sa.or_(User.email == email, User.username == username)
                )
            )
            if exists is not None:
                errors.append("That email or username is already registered.")

        if errors:
            for message in errors:
                flash(message, "error")
            return render_template(
                "auth/register.html", email=email, username=username
            )

        user = User(
            email=email,
            username=username,
            display_name=username,
            password_hash=hash_password(password),
            role=Role.USER,
        )
        db.session.add(user)
        db.session.commit()
        _record("register", user.id, f"new account {username}")

        flash("Account created. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Verify credentials; branch into the 2FA step when TOTP is enabled."""
    if current_user() is not None:
        return redirect(url_for("dashboard.home"))

    next_target = request.args.get("next") or request.form.get("next")

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")

        # Allow login by either email or username.
        user = db.session.scalar(
            sa.select(User).where(
                sa.or_(
                    User.email == identifier,
                    User.username == identifier,
                )
            )
        )

        if (
            user is None
            or not user.is_active
            or not verify_password(password, user.password_hash)
        ):
            # Identical message and timing path for every failure mode so we
            # do not leak which accounts exist.
            _record("login_failed", user.id if user else None, identifier)
            flash("Invalid credentials, or the account is inactive.", "error")
            return render_template(
                "auth/login.html", identifier=identifier, next=next_target
            )

        if user.totp_enabled:
            # First factor passed; stash the pending user and ask for the code.
            # TOTP takes precedence over Telegram approval when both are on.
            session.clear()
            session[PENDING_2FA_KEY] = user.id
            if next_target:
                session["pending_next"] = next_target
            return redirect(url_for("auth.two_factor"))

        if user.telegram_login_enabled and user.telegram_linked and tg.is_configured():
            # Second factor via Telegram: confirm button or fallback code.
            return _start_telegram_login(user, next_target)

        return _finish_login(user, next_target)

    return render_template("auth/login.html", next=next_target)


@auth_bp.route("/login/2fa", methods=["GET", "POST"])
def two_factor():
    """Second login step: verify the 6-digit TOTP code."""
    pending_id = session.get(PENDING_2FA_KEY)
    if pending_id is None:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_id)
    if user is None or not user.totp_enabled:
        session.pop(PENDING_2FA_KEY, None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "")
        if verify_totp(user.totp_secret or "", code):
            next_target = session.get("pending_next")
            login_user(user)  # clears the pending markers via session.clear()
            _record("login_2fa", user.id)
            _notify_signin(user)
            flash(f"Welcome back, {user.name}.", "success")
            return redirect(_safe_next(next_target))
        _record("login_2fa_failed", user.id)
        flash("Incorrect authentication code. Please try again.", "error")

    return render_template("auth/two_factor.html")


@auth_bp.route("/login/telegram")
def telegram_confirm():
    """Waiting page after a password when Telegram approval is required."""
    req_id = session.get(PENDING_TG_KEY)
    if req_id is None:
        return redirect(url_for("auth.login"))
    req = db.session.get(LoginRequest, req_id)
    if req is None:
        session.pop(PENDING_TG_KEY, None)
        return redirect(url_for("auth.login"))
    return render_template("auth/telegram_confirm.html")


@auth_bp.route("/login/telegram/status")
def telegram_status():
    """HTMX poll target: resolve the pending sign-in or keep waiting."""
    req_id = session.get(PENDING_TG_KEY)
    req = db.session.get(LoginRequest, req_id) if req_id else None
    if req is None:
        return _tg_redirect(url_for("auth.login"))

    if req.status == LoginRequestStatus.APPROVED:
        user = db.session.get(User, req.user_id)
        if user is None or not user.is_active:
            session.clear()
            return _tg_redirect(url_for("auth.login"))
        next_target = session.get("pending_next")
        login_user(user)  # clears pending markers via session.clear()
        _record("login_telegram", user.id)
        _notify_signin(user)
        flash(f"Welcome back, {user.name}.", "success")
        return _tg_redirect(_safe_next(next_target))

    if req.status == LoginRequestStatus.DENIED:
        session.pop(PENDING_TG_KEY, None)
        session.pop("pending_next", None)
        flash("Sign-in was denied from Telegram.", "error")
        return _tg_redirect(url_for("auth.login"))

    if req.is_expired:
        session.pop(PENDING_TG_KEY, None)
        session.pop("pending_next", None)
        flash("The sign-in request expired. Please sign in again.", "error")
        return _tg_redirect(url_for("auth.login"))

    # Still pending -> render the small "waiting" partial so HTMX keeps polling.
    return render_template("partials/telegram_waiting.html")


@auth_bp.route("/login/telegram/code", methods=["POST"])
def telegram_code():
    """Fallback: approve the pending sign-in by typing the 6-digit code."""
    req_id = session.get(PENDING_TG_KEY)
    req = db.session.get(LoginRequest, req_id) if req_id else None
    if req is None:
        return redirect(url_for("auth.login"))

    if not req.is_actionable:
        session.pop(PENDING_TG_KEY, None)
        session.pop("pending_next", None)
        flash("The sign-in request expired. Please sign in again.", "error")
        return redirect(url_for("auth.login"))

    code = request.form.get("code", "").strip().replace(" ", "")
    if code and hmac.compare_digest(code, req.code):
        req.status = LoginRequestStatus.APPROVED
        req.resolved_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()
        user = db.session.get(User, req.user_id)
        if user is None or not user.is_active:
            session.clear()
            return redirect(url_for("auth.login"))
        next_target = session.get("pending_next")
        login_user(user)
        _record("login_telegram_code", user.id)
        _notify_signin(user)
        flash(f"Welcome back, {user.name}.", "success")
        return redirect(_safe_next(next_target))

    flash("Incorrect code. Check Telegram and try again.", "error")
    return redirect(url_for("auth.telegram_confirm"))


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Log the current user out and return to the login page."""
    user = current_user()
    if user is not None:
        _record("logout", user.id)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
