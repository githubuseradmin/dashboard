"""Support blueprint: users open tickets; staff triage and reply."""

from __future__ import annotations

import sqlalchemy as sa
from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ..extensions import db
from ..models import (
    SUPPORT_STAFF_ROLES,
    SupportTicket,
    TicketMessage,
    TicketStatus,
    User,
)
from ..security import current_user, login_required

support_bp = Blueprint("support", __name__, url_prefix="/dashboard/support")


def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


def _can_view(ticket: SupportTicket, user: User) -> bool:
    """A ticket is visible to its owner or to any support staff member."""
    return ticket.user_id == user.id or user.role in SUPPORT_STAFF_ROLES


@support_bp.route("/")
@login_required
def index():
    """List the user's own tickets; staff additionally see all open tickets."""
    user = current_user()

    my_tickets = db.session.scalars(
        sa.select(SupportTicket)
        .where(SupportTicket.user_id == user.id)
        .order_by(SupportTicket.created_at.desc())
    ).all()

    staff_tickets = []
    if user.role in SUPPORT_STAFF_ROLES:
        staff_tickets = db.session.scalars(
            sa.select(SupportTicket)
            .where(SupportTicket.status != TicketStatus.CLOSED)
            .order_by(SupportTicket.created_at.desc())
        ).all()

    template = "partials/support.html" if _is_htmx() else "support/index.html"
    return render_template(
        template,
        my_tickets=my_tickets,
        staff_tickets=staff_tickets,
        is_staff=user.role in SUPPORT_STAFF_ROLES,
        statuses=list(TicketStatus),
        active_tab="support",
    )


@support_bp.route("/new", methods=["POST"])
@login_required
def create():
    """Open a new support ticket with its first message."""
    user = current_user()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()

    if not subject or not body:
        flash("Both a subject and a message are required.", "error")
        return redirect(url_for("support.index"))
    if len(subject) > 160:
        flash("Subject is too long (max 160 characters).", "error")
        return redirect(url_for("support.index"))

    ticket = SupportTicket(
        user_id=user.id, subject=subject, body=body, status=TicketStatus.OPEN
    )
    ticket.messages.append(
        TicketMessage(author_id=user.id, body=body, is_staff_reply=False)
    )
    db.session.add(ticket)
    db.session.commit()
    flash("Your ticket has been submitted.", "success")
    return redirect(url_for("support.view", ticket_id=ticket.id))


@support_bp.route("/<int:ticket_id>")
@login_required
def view(ticket_id: int):
    """Show a single ticket thread."""
    user = current_user()
    ticket = db.session.get(SupportTicket, ticket_id)
    if ticket is None:
        abort(404)
    if not _can_view(ticket, user):
        abort(403)

    return render_template(
        "support/thread.html",
        ticket=ticket,
        is_staff=user.role in SUPPORT_STAFF_ROLES,
        statuses=list(TicketStatus),
        active_tab="support",
    )


@support_bp.route("/<int:ticket_id>/reply", methods=["POST"])
@login_required
def reply(ticket_id: int):
    """Append a message to a ticket thread (owner or staff)."""
    user = current_user()
    ticket = db.session.get(SupportTicket, ticket_id)
    if ticket is None:
        abort(404)
    if not _can_view(ticket, user):
        abort(403)

    body = request.form.get("body", "").strip()
    if not body:
        flash("Reply cannot be empty.", "error")
        return redirect(url_for("support.view", ticket_id=ticket.id))

    is_staff_reply = user.role in SUPPORT_STAFF_ROLES and ticket.user_id != user.id
    ticket.messages.append(
        TicketMessage(author_id=user.id, body=body, is_staff_reply=is_staff_reply)
    )
    # A staff reply moves an open ticket to "pending" (awaiting the user);
    # a user reply on a pending ticket reopens it.
    if is_staff_reply and ticket.status == TicketStatus.OPEN:
        ticket.status = TicketStatus.PENDING
    elif not is_staff_reply and ticket.status == TicketStatus.PENDING:
        ticket.status = TicketStatus.OPEN
    db.session.commit()
    flash("Reply added.", "success")
    return redirect(url_for("support.view", ticket_id=ticket.id))


@support_bp.route("/<int:ticket_id>/status", methods=["POST"])
@login_required
def set_status(ticket_id: int):
    """Change a ticket's status. Staff may set any status; owners may close."""
    user = current_user()
    ticket = db.session.get(SupportTicket, ticket_id)
    if ticket is None:
        abort(404)

    is_staff = user.role in SUPPORT_STAFF_ROLES
    is_owner = ticket.user_id == user.id
    if not (is_staff or is_owner):
        abort(403)

    raw_status = request.form.get("status", "")
    try:
        new_status = TicketStatus(raw_status)
    except ValueError:
        flash("Unknown status.", "error")
        return redirect(url_for("support.view", ticket_id=ticket.id))

    # Ticket owners (non-staff) are only allowed to close their own ticket.
    if not is_staff and new_status != TicketStatus.CLOSED:
        abort(403)

    ticket.status = new_status
    db.session.commit()
    flash(f"Ticket marked as {new_status.label}.", "success")
    return redirect(url_for("support.view", ticket_id=ticket.id))
