"""Admin blueprint: user management and simple statistics (staff only)."""

from __future__ import annotations

import sqlalchemy as sa
from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..extensions import db
from ..models import (
    ADMIN_ROLES,
    AuditLog,
    Role,
    SupportTicket,
    TicketStatus,
    User,
)
from ..security import current_user, role_required

admin_bp = Blueprint("admin", __name__, url_prefix="/dashboard/admin")


def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


@admin_bp.route("/")
@role_required(*ADMIN_ROLES)
def index():
    """User list with search plus headline counts."""
    query = request.args.get("q", "").strip()

    stmt = sa.select(User).order_by(User.created_at.desc())
    if query:
        like = f"%{query}%"
        stmt = stmt.where(
            sa.or_(
                User.email.ilike(like),
                User.username.ilike(like),
                User.display_name.ilike(like),
            )
        )
    users = db.session.scalars(stmt).all()

    stats = {
        "total_users": db.session.scalar(sa.select(sa.func.count()).select_from(User)),
        "active_users": db.session.scalar(
            sa.select(sa.func.count()).select_from(User).where(User.is_active.is_(True))
        ),
        "open_tickets": db.session.scalar(
            sa.select(sa.func.count())
            .select_from(SupportTicket)
            .where(SupportTicket.status != TicketStatus.CLOSED)
        ),
        "two_factor_users": db.session.scalar(
            sa.select(sa.func.count())
            .select_from(User)
            .where(User.totp_enabled.is_(True))
        ),
    }

    template = "partials/admin_users.html" if _is_htmx() else "admin/index.html"
    return render_template(
        template,
        users=users,
        stats=stats,
        query=query,
        roles=list(Role),
        active_tab="admin",
    )


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@role_required(*ADMIN_ROLES)
def change_role(user_id: int):
    """Change a user's role. Admins only may grant the admin role."""
    actor = current_user()
    target = db.session.get(User, user_id)
    if target is None:
        flash("User not found.", "error")
        return redirect(url_for("admin.index"))

    raw_role = request.form.get("role", "")
    try:
        new_role = Role(raw_role)
    except ValueError:
        flash("Unknown role.", "error")
        return redirect(url_for("admin.index"))

    # Only full admins may assign or revoke the admin role.
    if (new_role == Role.ADMIN or target.role == Role.ADMIN) and actor.role != Role.ADMIN:
        flash("Only an admin can manage the admin role.", "error")
        return redirect(url_for("admin.index"))

    # Guard against an admin demoting themselves and locking everyone out.
    if target.id == actor.id and new_role != Role.ADMIN and actor.role == Role.ADMIN:
        remaining_admins = db.session.scalar(
            sa.select(sa.func.count())
            .select_from(User)
            .where(User.role == Role.ADMIN, User.id != actor.id)
        )
        if not remaining_admins:
            flash("You are the only admin -- assign another admin first.", "error")
            return redirect(url_for("admin.index"))

    target.role = new_role
    db.session.add(
        AuditLog(
            user_id=actor.id,
            action="role_changed",
            detail=f"{target.username} -> {new_role.value}",
        )
    )
    db.session.commit()
    flash(f"{target.name}'s role is now {new_role.label}.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@role_required(*ADMIN_ROLES)
def toggle_active(user_id: int):
    """Activate or deactivate an account (cannot deactivate yourself)."""
    actor = current_user()
    target = db.session.get(User, user_id)
    if target is None:
        flash("User not found.", "error")
        return redirect(url_for("admin.index"))

    if target.id == actor.id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin.index"))

    # Moderators may not deactivate admins.
    if target.role == Role.ADMIN and actor.role != Role.ADMIN:
        flash("Only an admin can change an admin account.", "error")
        return redirect(url_for("admin.index"))

    target.is_active = not target.is_active
    state = "activated" if target.is_active else "deactivated"
    db.session.add(
        AuditLog(user_id=actor.id, action="account_" + state, detail=target.username)
    )
    db.session.commit()
    flash(f"{target.name}'s account has been {state}.", "success")
    return redirect(url_for("admin.index"))
