"""Database bootstrap and demo-data seeder.

Running ``python seed.py``:
  1. creates every table,
  2. seeds a demo admin plus a couple of sample accounts and a ticket,
  3. PRINTS the demo credentials so you can sign in immediately.

It is safe to run repeatedly: existing accounts are left untouched.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

import sqlalchemy as sa  # noqa: E402

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.migrate import ensure_schema  # noqa: E402
from app.models import Role, SupportTicket, TicketMessage, TicketStatus, User  # noqa: E402
from app.security import hash_password  # noqa: E402

# Demo credentials. Override the admin password via SEED_ADMIN_PASSWORD.
ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@example.com")
ADMIN_USERNAME = os.environ.get("SEED_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD", "Admin12345!")

DEMO_ACCOUNTS = [
    # (username, email, password, role, display_name)
    ("supporter", "supporter@example.com", "Support12345!", Role.SUPPORTER, "Sam Supporter"),
    ("member", "member@example.com", "Member12345!", Role.USER, "Mia Member"),
]


def _get_or_create_user(username, email, password, role, display_name):
    """Return an existing user by username/email, or create a new one."""
    user = db.session.scalar(
        sa.select(User).where(
            sa.or_(User.username == username, User.email == email)
        )
    )
    if user is not None:
        return user, False
    user = User(
        username=username,
        email=email,
        display_name=display_name,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    db.session.add(user)
    db.session.flush()
    return user, True


def seed() -> None:
    app = create_app()
    with app.app_context():
        # Create new tables and add any columns missing from an older database
        # (e.g. the Telegram fields), so re-seeding upgrades the schema in place.
        added = ensure_schema(db.engine)
        if added:
            print("Schema upgraded; added columns:", ", ".join(added))

        admin, admin_created = _get_or_create_user(
            ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD, Role.ADMIN, "Site Admin"
        )

        created_demo = []
        for username, email, password, role, display in DEMO_ACCOUNTS:
            user, was_created = _get_or_create_user(
                username, email, password, role, display
            )
            if was_created:
                created_demo.append((user, password))

        # Seed one sample ticket from the member account, if none exists yet.
        member = db.session.scalar(
            sa.select(User).where(User.username == "member")
        )
        if member is not None:
            has_ticket = db.session.scalar(
                sa.select(sa.func.count())
                .select_from(SupportTicket)
                .where(SupportTicket.user_id == member.id)
            )
            if not has_ticket:
                ticket = SupportTicket(
                    user_id=member.id,
                    subject="How do I enable two-factor authentication?",
                    body="I would like to secure my account with an authenticator app.",
                    status=TicketStatus.OPEN,
                )
                ticket.messages.append(
                    TicketMessage(
                        author_id=member.id,
                        body="I would like to secure my account with an authenticator app.",
                        is_staff_reply=False,
                    )
                )
                db.session.add(ticket)

        db.session.commit()

        # ------------------------------------------------------------------
        # Print the demo credentials.
        # ------------------------------------------------------------------
        print("=" * 60)
        print("Database ready. Demo credentials:")
        print("-" * 60)
        if admin_created:
            print(f"  ADMIN     login: {ADMIN_EMAIL}")
            print(f"            password: {ADMIN_PASSWORD}")
        else:
            print(f"  ADMIN     login: {ADMIN_EMAIL} (already existed)")
        for user, password in created_demo:
            print(f"  {user.role.label.upper():9} login: {user.email}")
            print(f"            password: {password}")
        if not created_demo and not admin_created:
            print("  (all demo accounts already existed -- nothing changed)")
        print("=" * 60)
        print("Start the app with:  python run.py")
        print("Then open:           http://127.0.0.1:5000/dashboard")
        print("=" * 60)


if __name__ == "__main__":
    seed()
