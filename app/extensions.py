"""Shared extension instances and third-party compatibility shims.

Keeping these in a dedicated module avoids circular imports: blueprints and
models import ``db`` from here, while the application factory in
``app/__init__.py`` binds it to the concrete Flask app.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# bcrypt / passlib compatibility shim
# ---------------------------------------------------------------------------
# passlib 1.7.4 (the latest release) was written against the bcrypt 3.x API.
# Two things break on bcrypt >= 4.1 / 5.x:
#   1. passlib reads ``bcrypt.__about__.__version__``, which newer bcrypt
#      no longer exposes.
#   2. passlib runs a one-time startup self-test ("detect_wrap_bug") that
#      hashes a >72-byte probe string. bcrypt >= 4.1 raises ``ValueError``
#      for secrets longer than 72 bytes instead of silently truncating, so
#      the self-test crashes before any real password is ever hashed.
#
# We restore the two legacy behaviours passlib relies on. This is applied at
# import time, before passlib's bcrypt backend is initialised, and only
# affects the startup probe -- real password hashing is unchanged and the
# resulting hashes are standard ``$2b$`` bcrypt strings.
import types

import bcrypt as _bcrypt

if not hasattr(_bcrypt, "__about__"):  # pragma: no cover - depends on bcrypt version
    _bcrypt.__about__ = types.SimpleNamespace(
        __version__=getattr(_bcrypt, "__version__", "unknown")
    )

if not getattr(_bcrypt, "_passlib_truncate_shim", False):  # pragma: no cover
    _orig_hashpw = _bcrypt.hashpw

    def _hashpw_truncating(secret, salt):
        # Mirror the pre-4.1 silent truncation so passlib's startup probe and
        # any over-length input behave the way passlib 1.7.4 expects.
        if isinstance(secret, (bytes, bytearray)) and len(secret) > 72:
            secret = bytes(secret[:72])
        return _orig_hashpw(secret, salt)

    _bcrypt.hashpw = _hashpw_truncating
    _bcrypt._passlib_truncate_shim = True

# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------
from sqlalchemy.orm import DeclarativeBase  # noqa: E402
import sqlalchemy as sa  # noqa: E402
from sqlalchemy.orm import scoped_session, sessionmaker  # noqa: E402


class Base(DeclarativeBase):
    """Declarative base class for all ORM models (SQLAlchemy 2.x style)."""


class Database:
    """Thin SQLAlchemy 2.x integration for Flask.

    Provides an engine plus a request-scoped session. Kept deliberately small
    and framework-agnostic so the project stays dependency-light (no
    Flask-SQLAlchemy required).
    """

    def __init__(self) -> None:
        self.engine: sa.Engine | None = None
        self.session: scoped_session | None = None
        self._factory: sessionmaker | None = None

    def init_app(self, app) -> None:
        """Create the engine and bind a scoped session to the Flask app."""
        url = app.config["SQLALCHEMY_DATABASE_URI"]

        engine_kwargs: dict = {"future": True, "pool_pre_ping": True}
        # SQLite needs a special flag to be used across threads (dev server).
        if url.startswith("sqlite"):
            engine_kwargs["connect_args"] = {"check_same_thread": False}

        self.engine = sa.create_engine(url, **engine_kwargs)
        self._factory = sessionmaker(
            bind=self.engine, autoflush=False, expire_on_commit=False, future=True
        )
        # ``scoped_session`` gives one session per request thread.
        self.session = scoped_session(self._factory)

        # Ensure the session is returned to the pool at the end of each request.
        @app.teardown_appcontext
        def _remove_session(exception=None):  # noqa: ANN001
            if self.session is not None:
                self.session.remove()

    def create_all(self) -> None:
        """Create every table declared on ``Base.metadata``."""
        assert self.engine is not None, "Database.init_app must be called first"
        Base.metadata.create_all(self.engine)

    def drop_all(self) -> None:
        """Drop every table (used by tests for a clean slate)."""
        assert self.engine is not None, "Database.init_app must be called first"
        Base.metadata.drop_all(self.engine)


# The single shared database instance imported across the app.
db = Database()
