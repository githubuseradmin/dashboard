"""Authentication blueprint: register, login (with optional 2FA) and logout."""

from __future__ import annotations

import re

import sqlalchemy as sa
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..extensions import db
from ..models import AuditLog, Role, User
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
            session.clear()
            session[PENDING_2FA_KEY] = user.id
            if next_target:
                session["pending_next"] = next_target
            return redirect(url_for("auth.two_factor"))

        login_user(user)
        _record("login", user.id)
        flash(f"Welcome back, {user.name}.", "success")
        return redirect(_safe_next(next_target))

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
            flash(f"Welcome back, {user.name}.", "success")
            return redirect(_safe_next(next_target))
        _record("login_2fa_failed", user.id)
        flash("Incorrect authentication code. Please try again.", "error")

    return render_template("auth/two_factor.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Log the current user out and return to the login page."""
    user = current_user()
    if user is not None:
        _record("logout", user.id)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
