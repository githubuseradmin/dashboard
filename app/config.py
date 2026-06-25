"""Application configuration.

All settings are environment-driven so the same code runs unchanged in
development, testing and production. Values are read once at import time from
the process environment (which python-dotenv populates from a local ``.env``
file when present).
"""

from __future__ import annotations

import os
from datetime import timedelta


def _bool(value: str | None, default: bool = False) -> bool:
    """Parse a human-friendly truthy string into a boolean."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class BaseConfig:
    """Settings shared by every environment."""

    # Secret used to sign session cookies and CSRF tokens. MUST be overridden
    # in production via the SECRET_KEY environment variable.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-change-me")

    # Database. SQLite by default; switch to MySQL by setting DATABASE_URL, e.g.
    #   mysql+pymysql://user:password@host:3306/dbname?charset=utf8mb4
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///dashboard.db"
    )

    # Human-readable label shown in the UI and TOTP issuer name.
    APP_NAME = os.environ.get("APP_NAME", "Dashboard")

    # Session / cookie hardening.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Only send the session cookie over HTTPS when explicitly enabled (production).
    SESSION_COOKIE_SECURE = _bool(os.environ.get("SESSION_COOKIE_SECURE"), False)
    PERMANENT_SESSION_LIFETIME = timedelta(
        days=int(os.environ.get("SESSION_LIFETIME_DAYS", "7"))
    )

    # Bcrypt cost factor (work rounds). Higher is slower and more secure.
    BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

    TESTING = False


class DevelopmentConfig(BaseConfig):
    """Local development defaults."""

    DEBUG = True


class ProductionConfig(BaseConfig):
    """Production defaults: stricter cookie security."""

    DEBUG = False
    SESSION_COOKIE_SECURE = _bool(os.environ.get("SESSION_COOKIE_SECURE"), True)


class TestingConfig(BaseConfig):
    """Settings for the unit-test suite (fast, in-memory, no real secrets)."""

    TESTING = True
    DEBUG = False
    # Each test app gets a private in-memory database.
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # Keep the test suite fast: a low cost factor still exercises real bcrypt.
    BCRYPT_ROUNDS = 4
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-key"


# Lookup table used by the application factory.
CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def resolve_config(name: str | None = None):
    """Return the config class for ``name`` or the FLASK_ENV environment value."""
    key = (name or os.environ.get("FLASK_ENV", "development")).lower()
    return CONFIG_MAP.get(key, DevelopmentConfig)
