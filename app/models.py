"""SQLAlchemy ORM models (SQLAlchemy 2.x typed mapping style).

The schema is intentionally small and explicit:

* ``User``         -- account, role and optional TOTP 2FA secret.
* ``SupportTicket``-- a help request opened by a user.
* ``TicketMessage``-- a single message in a ticket thread.
* ``AuditLog``     -- optional security/audit trail of notable actions.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional

import sqlalchemy as sa
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .extensions import Base


def _utcnow() -> datetime:
    """Timezone-aware UTC timestamp used for all ``created_at`` columns."""
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    """User roles, ordered from least to most privileged.

    Inheriting from ``str`` makes the enum serialise cleanly to the database
    and to templates while still giving us a real enum to compare against.
    """

    USER = "user"
    SUPPORTER = "supporter"
    MODERATOR = "moderator"
    ADMIN = "admin"

    @property
    def label(self) -> str:
        """Human-friendly title-cased label for the UI."""
        return self.value.capitalize()


# Roles allowed to view the staff-only admin area.
ADMIN_ROLES = {Role.MODERATOR, Role.ADMIN}
# Roles allowed to triage and answer support tickets.
SUPPORT_STAFF_ROLES = {Role.SUPPORTER, Role.MODERATOR, Role.ADMIN}


class TicketStatus(str, enum.Enum):
    """Lifecycle states of a support ticket."""

    OPEN = "open"
    PENDING = "pending"
    CLOSED = "closed"

    @property
    def label(self) -> str:
        return self.value.capitalize()


class User(Base):
    """An application account."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(sa.String(255), unique=True, index=True)
    username: Mapped[str] = mapped_column(sa.String(80), unique=True, index=True)
    # Optional friendly display name shown around the UI.
    display_name: Mapped[Optional[str]] = mapped_column(sa.String(120), default=None)
    password_hash: Mapped[str] = mapped_column(sa.String(255))
    role: Mapped[Role] = mapped_column(
        sa.Enum(Role, native_enum=False, length=20), default=Role.USER
    )
    is_active: Mapped[bool] = mapped_column(default=True)

    # Two-factor authentication (TOTP). ``totp_secret`` is the base32 shared
    # secret; ``totp_enabled`` marks whether the user has finished enrolment.
    totp_secret: Mapped[Optional[str]] = mapped_column(sa.String(64), default=None)
    totp_enabled: Mapped[bool] = mapped_column(default=False)

    created_at: Mapped[datetime] = mapped_column(default=_utcnow)

    tickets: Mapped[list["SupportTicket"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    # -- convenience helpers -------------------------------------------------
    @property
    def name(self) -> str:
        """Best display label for the user."""
        return self.display_name or self.username

    @property
    def initials(self) -> str:
        """Up to two uppercase initials for the avatar bubble."""
        source = (self.display_name or self.username or self.email).strip()
        parts = source.split()
        if len(parts) >= 2:
            return (parts[0][0] + parts[1][0]).upper()
        return source[:2].upper()

    @property
    def is_staff(self) -> bool:
        """True for any role that can access staff areas."""
        return self.role in (ADMIN_ROLES | SUPPORT_STAFF_ROLES)

    def has_role(self, *roles: Role) -> bool:
        return self.role in roles

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<User {self.username!r} role={self.role.value}>"


class SupportTicket(Base):
    """A support request raised by a user."""

    __tablename__ = "support_tickets"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    subject: Mapped[str] = mapped_column(sa.String(160))
    body: Mapped[str] = mapped_column(sa.Text)
    status: Mapped[TicketStatus] = mapped_column(
        sa.Enum(TicketStatus, native_enum=False, length=20), default=TicketStatus.OPEN
    )
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)

    user: Mapped["User"] = relationship(back_populates="tickets")
    messages: Mapped[list["TicketMessage"]] = relationship(
        back_populates="ticket",
        cascade="all, delete-orphan",
        order_by="TicketMessage.created_at",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<SupportTicket #{self.id} {self.status.value}>"


class TicketMessage(Base):
    """A single message in a support ticket thread."""

    __tablename__ = "ticket_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(
        ForeignKey("support_tickets.id"), index=True
    )
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(sa.Text)
    # True when written by support staff (rendered differently in the thread).
    is_staff_reply: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)

    ticket: Mapped["SupportTicket"] = relationship(back_populates="messages")
    author: Mapped["User"] = relationship()

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<TicketMessage #{self.id} ticket={self.ticket_id}>"


class AuditLog(Base):
    """Lightweight audit trail of security-relevant actions.

    Optional but handy: records who did what (e.g. login, role change) so an
    admin can review account activity.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Nullable: some events (e.g. failed login for unknown user) have no user.
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id"), default=None, index=True
    )
    action: Mapped[str] = mapped_column(sa.String(80))
    detail: Mapped[Optional[str]] = mapped_column(sa.String(255), default=None)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<AuditLog {self.action!r} user={self.user_id}>"
