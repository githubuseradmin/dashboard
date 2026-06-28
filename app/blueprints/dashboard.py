"""Dashboard blueprint: home feed, profile, settings and 2FA management.

Tab content is served both as full pages and, when requested via HTMX
(``HX-Request`` header), as bare partials so switching tabs feels instant
without a full reload.
"""

from __future__ import annotations

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

from .. import telegram as tg
from ..extensions import db
from ..models import (
    ADMIN_ROLES,
    SUPPORT_STAFF_ROLES,
    AuditLog,
    SupportTicket,
    TicketStatus,
    User,
)
from ..security import (
    current_user,
    generate_totp_secret,
    hash_password,
    login_required,
    qr_svg,
    totp_qr_svg,
    verify_password,
    verify_totp,
)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

# Session key holding a not-yet-confirmed TOTP secret during 2FA enrolment.
_PENDING_TOTP_KEY = "pending_totp_secret"


def _telegram_context() -> dict:
    """Shared Telegram bits for the settings page (whether the feature is on)."""
    return {
        "telegram_configured": tg.is_configured(),
        "telegram_bot": tg.bot_username(),
    }


def _is_htmx() -> bool:
    """True when the request originates from an HTMX swap."""
    return request.headers.get("HX-Request") == "true"


def _render(full_template: str, partial_template: str, **context):
    """Render the partial for HTMX requests, the full page otherwise."""
    template = partial_template if _is_htmx() else full_template
    return render_template(template, **context)


@dashboard_bp.route("/")
@login_required
def home():
    """Activity feed: recent account events and a few quick stats."""
    user = current_user()

    events = db.session.scalars(
        sa.select(AuditLog)
        .where(AuditLog.user_id == user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(10)
    ).all()

    open_tickets = db.session.scalar(
        sa.select(sa.func.count())
        .select_from(SupportTicket)
        .where(
            SupportTicket.user_id == user.id,
            SupportTicket.status != TicketStatus.CLOSED,
        )
    )

    stats = {
        "open_tickets": open_tickets or 0,
        "two_factor": "On" if user.totp_enabled else "Off",
        "role": user.role.label,
    }

    return _render(
        "dashboard/home.html",
        "partials/home.html",
        events=events,
        stats=stats,
        active_tab="home",
    )


@dashboard_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """View and edit the display name."""
    user = current_user()

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        if not display_name:
            flash("Display name cannot be empty.", "error")
        elif len(display_name) > 120:
            flash("Display name is too long (max 120 characters).", "error")
        else:
            user.display_name = display_name
            db.session.commit()
            flash("Profile updated.", "success")

    return _render(
        "dashboard/profile.html",
        "partials/profile.html",
        user=user,
        active_tab="profile",
    )


@dashboard_bp.route("/settings")
@login_required
def settings():
    """Settings hub: password change, 2FA and Telegram management."""
    user = current_user()
    return _render(
        "dashboard/settings.html",
        "partials/settings.html",
        user=user,
        active_tab="settings",
        **_telegram_context(),
    )


@dashboard_bp.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    """Change the current user's password after verifying the old one."""
    user = current_user()
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if not verify_password(current, user.password_hash):
        flash("Your current password is incorrect.", "error")
    elif len(new) < 8:
        flash("New password must be at least 8 characters long.", "error")
    elif new != confirm:
        flash("New passwords do not match.", "error")
    else:
        user.password_hash = hash_password(new)
        db.session.add(AuditLog(user_id=user.id, action="password_changed"))
        db.session.commit()
        tg.notify(user, "🔑 Your password was just changed.")
        flash("Password changed successfully.", "success")

    return redirect(url_for("dashboard.settings"))


@dashboard_bp.route("/settings/2fa/setup", methods=["POST"])
@login_required
def two_factor_setup():
    """Begin 2FA enrolment: generate a secret and show a QR code to scan."""
    user = current_user()
    if user.totp_enabled:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("dashboard.settings"))

    secret = generate_totp_secret()
    session[_PENDING_TOTP_KEY] = secret

    issuer = request.host or "Dashboard"
    qr_svg = totp_qr_svg(secret, account_name=user.email, issuer=issuer)

    return render_template(
        "dashboard/two_factor_setup.html",
        user=user,
        secret=secret,
        qr_svg=qr_svg,
        active_tab="settings",
    )


@dashboard_bp.route("/settings/2fa/enable", methods=["POST"])
@login_required
def two_factor_enable():
    """Confirm enrolment by verifying a code generated from the new secret."""
    user = current_user()
    secret = session.get(_PENDING_TOTP_KEY)
    code = request.form.get("code", "")

    if not secret:
        flash("Two-factor setup expired. Please start again.", "error")
    elif verify_totp(secret, code):
        user.totp_secret = secret
        user.totp_enabled = True
        session.pop(_PENDING_TOTP_KEY, None)
        db.session.add(AuditLog(user_id=user.id, action="2fa_enabled"))
        db.session.commit()
        flash("Two-factor authentication is now enabled.", "success")
        return redirect(url_for("dashboard.settings"))
    else:
        flash("That code did not match. Please try again.", "error")

    # Re-show the setup screen with the same secret on failure.
    issuer = request.host or "Dashboard"
    qr_svg = totp_qr_svg(secret, account_name=user.email, issuer=issuer) if secret else ""
    return render_template(
        "dashboard/two_factor_setup.html",
        user=user,
        secret=secret,
        qr_svg=qr_svg,
        active_tab="settings",
    )


@dashboard_bp.route("/settings/2fa/disable", methods=["POST"])
@login_required
def two_factor_disable():
    """Turn off 2FA after re-verifying the user's password."""
    user = current_user()
    password = request.form.get("password", "")

    if not user.totp_enabled:
        flash("Two-factor authentication is not enabled.", "info")
    elif not verify_password(password, user.password_hash):
        flash("Incorrect password. Two-factor authentication remains enabled.", "error")
    else:
        user.totp_enabled = False
        user.totp_secret = None
        db.session.add(AuditLog(user_id=user.id, action="2fa_disabled"))
        db.session.commit()
        flash("Two-factor authentication has been disabled.", "success")

    return redirect(url_for("dashboard.settings"))


# ---------------------------------------------------------------------------
# Telegram account management
# ---------------------------------------------------------------------------
@dashboard_bp.route("/settings/telegram/link", methods=["POST"])
@login_required
def telegram_link():
    """Show a one-time deep link + QR to connect a Telegram account."""
    user = current_user()
    if not tg.is_configured():
        flash("Telegram is not configured on this server.", "error")
        return redirect(url_for("dashboard.settings"))
    if user.telegram_linked:
        flash("A Telegram account is already linked.", "info")
        return redirect(url_for("dashboard.settings"))
    if not tg.bot_username():
        flash("The bot username is not configured; cannot build the link.", "error")
        return redirect(url_for("dashboard.settings"))

    token = tg.make_link_token(user.id)
    link_url = f"https://t.me/{tg.bot_username()}?start={token}"

    return _render(
        "dashboard/settings.html",
        "partials/settings.html",
        user=user,
        active_tab="settings",
        link_url=link_url,
        link_qr=qr_svg(link_url),
        **_telegram_context(),
    )


@dashboard_bp.route("/settings/telegram/unlink", methods=["POST"])
@login_required
def telegram_unlink():
    """Disconnect the linked Telegram account and turn its features off."""
    user = current_user()
    if user.telegram_linked:
        tg.notify(user, "🔌 This account was unlinked from the dashboard.")
        user.telegram_id = None
        user.telegram_username = None
        user.telegram_login_enabled = False
        db.session.add(AuditLog(user_id=user.id, action="telegram_unlinked"))
        db.session.commit()
        flash("Telegram account unlinked.", "success")
    else:
        flash("No Telegram account is linked.", "info")
    return redirect(url_for("dashboard.settings"))


@dashboard_bp.route("/settings/telegram/login", methods=["POST"])
@login_required
def telegram_toggle_login():
    """Enable/disable requiring a Telegram approval at sign-in."""
    user = current_user()
    if not user.telegram_linked:
        flash("Link a Telegram account first.", "error")
        return redirect(url_for("dashboard.settings"))
    user.telegram_login_enabled = not user.telegram_login_enabled
    db.session.add(
        AuditLog(
            user_id=user.id,
            action="telegram_login_toggled",
            detail="on" if user.telegram_login_enabled else "off",
        )
    )
    db.session.commit()
    flash(
        "Telegram sign-in approval is now "
        + ("enabled." if user.telegram_login_enabled else "disabled."),
        "success",
    )
    return redirect(url_for("dashboard.settings"))


@dashboard_bp.route("/settings/telegram/notify", methods=["POST"])
@login_required
def telegram_toggle_notify():
    """Enable/disable Telegram account notifications."""
    user = current_user()
    if not user.telegram_linked:
        flash("Link a Telegram account first.", "error")
        return redirect(url_for("dashboard.settings"))
    user.telegram_notify = not user.telegram_notify
    db.session.commit()
    flash(
        "Telegram notifications are now "
        + ("on." if user.telegram_notify else "off."),
        "success",
    )
    return redirect(url_for("dashboard.settings"))
