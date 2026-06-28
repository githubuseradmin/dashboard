"""Tiny idempotent schema helper for the dev/demo database.

``create_all`` makes new tables but never ALTERs existing ones, so adding
columns to a model (e.g. the Telegram fields on ``User``) would leave an older
database missing them. ``ensure_schema`` creates any new tables and adds any
missing columns, so ``python seed.py`` upgrades an existing SQLite/MySQL DB in
place -- no migration framework required for this small project.
"""

from __future__ import annotations

import sqlalchemy as sa

from .extensions import Base

# Columns introduced after the initial release, keyed by table name. The DDL is
# written to be valid on both SQLite and MySQL (BOOLEAN -> TINYINT(1) on MySQL),
# and every column is nullable / defaulted so existing rows upgrade cleanly.
_ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "users": {
        "telegram_id": "BIGINT",
        "telegram_username": "VARCHAR(64)",
        "telegram_login_enabled": "BOOLEAN DEFAULT 0",
        "telegram_notify": "BOOLEAN DEFAULT 1",
    },
}


def ensure_schema(engine: sa.Engine) -> list[str]:
    """Create new tables and add any missing columns. Returns what changed."""
    Base.metadata.create_all(engine)

    changed: list[str] = []
    inspector = sa.inspect(engine)
    tables = set(inspector.get_table_names())

    for table, columns in _ADDED_COLUMNS.items():
        if table not in tables:
            # create_all already built it with every column present.
            continue
        existing = {col["name"] for col in inspector.get_columns(table)}
        for name, ddl in columns.items():
            if name in existing:
                continue
            with engine.begin() as conn:
                conn.execute(sa.text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
            changed.append(f"{table}.{name}")

    return changed
