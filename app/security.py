"""Security helpers: password hashing, TOTP 2FA, CSRF and access control.

This module is the single place where authentication and authorisation logic
lives so it can be unit-tested in isolation and reasoned about easily.
"""

from __future__ import annotations

import hmac
import io
import secrets
from functools import wraps
from typing import Callable, Optional

import pyotp
import segno
from flask import (
    abort,
    current_app,
    flash,
    g,
    redirect,
    request,
    session,
    url_for,
)
from passlib.context import CryptContext

from .extensions import db
from .models import Role, User

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
# A passlib CryptContext keeps password handling declarative: bcrypt is the
# active scheme. The bcrypt cost factor is read from app config; per-rounds
# contexts are derived with ``CryptContext.using`` and cached so we configure
# the work factor once rather than on every hash call.
_DEFAULT_ROUNDS = 12
_pwd_context = CryptContext(
    schemes=["bcrypt"], deprecated="auto", bcrypt__default_rounds=_DEFAULT_ROUNDS
)
# Cache of rounds -> CryptContext to avoid rebuilding handlers repeatedly.
_context_cache: dict[int, CryptContext] = {_DEFAULT_ROUNDS: _pwd_context}


def _context_for_rounds(rounds: int) -> CryptContext:
    """Return a CryptContext configured for ``rounds`` bcrypt cost (cached)."""
    ctx = _context_cache.get(rounds)
    if ctx is None:
        ctx = _pwd_context.copy(bcrypt__default_rounds=rounds)
        _context_cache[rounds] = ctx
    return ctx


def hash_password(password: str) -> str:
    """Return a salted bcrypt hash for ``password``.

    The work factor comes from ``BCRYPT_ROUNDS`` in config when an application
    context is active, otherwise a safe default of 12 rounds is used.
    """
    rounds = _DEFAULT_ROUNDS
    try:
        rounds = int(current_app.config.get("BCRYPT_ROUNDS", _DEFAULT_ROUNDS))
    except RuntimeError:
        # No application context (e.g. a standalone unit test); use the default.
        pass
    return _context_for_rounds(rounds).hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time check of ``password`` against a stored bcrypt hash."""
    if not password_hash:
        return False
    try:
        return _pwd_context.verify(password, password_hash)
    except ValueError:
        # Malformed/unknown hash format -> treat as a failed verification.
        return False


# ---------------------------------------------------------------------------
# TOTP two-factor authentication
# ---------------------------------------------------------------------------
def generate_totp_secret() -> str:
    """Generate a fresh random base32 TOTP secret."""
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account_name: str, issuer: str) -> str:
    """Build the ``otpauth://`` URI an authenticator app scans to enrol."""
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def totp_qr_svg(secret: str, account_name: str, issuer: str) -> str:
    """Return an inline SVG QR code (as a string) for the provisioning URI.

    The QR is rendered with segno and never includes the secret in plain text,
    only the standard otpauth URI that authenticator apps expect.
    """
    uri = totp_provisioning_uri(secret, account_name, issuer)
    qr = segno.make(uri, error="m")

    # segno's SVG serializer writes bytes, so use a binary buffer and decode.
    # ``xmldecl=False`` so the fragment can be embedded directly in HTML.
    buffer = io.BytesIO()
    qr.save(buffer, kind="svg", xmldecl=False, scale=4, border=2)
    return buffer.getvalue().decode("utf-8")


def verify_totp(secret: str, code: str) -> bool:
    """Validate a 6-digit TOTP ``code`` against ``secret``.

    A ``valid_window`` of 1 tolerates a 30-second clock skew in either
    direction, which is standard for TOTP usability.
    """
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# ---------------------------------------------------------------------------
# CSRF protection (manual signed-token implementation, no extra dependency)
# ---------------------------------------------------------------------------
_CSRF_SESSION_KEY = "_csrf_token"


def get_csrf_token() -> str:
    """Return the per-session CSRF token, creating one on first use."""
    token = session.get(_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSRF_SESSION_KEY] = token
    return token


def validate_csrf(submitted: Optional[str]) -> bool:
    """Constant-time comparison of a submitted token with the session token."""
    expected = session.get(_CSRF_SESSION_KEY)
    if not expected or not submitted:
        return False
    return hmac.compare_digest(str(expected), str(submitted))


# ---------------------------------------------------------------------------
# Session / current-user helpers
# ---------------------------------------------------------------------------
_USER_SESSION_KEY = "user_id"
# Marks a half-finished login waiting for the second (TOTP) factor.
PENDING_2FA_KEY = "pending_2fa_user_id"


def login_user(user: User) -> None:
    """Mark ``user`` as fully authenticated for the current session."""
    session.clear()
    session[_USER_SESSION_KEY] = user.id
    session.permanent = True


def logout_user() -> None:
    """Clear all authentication state from the session."""
    session.clear()


def current_user() -> Optional[User]:
    """Return the logged-in ``User`` for this request, or ``None``.

    The lookup is cached on Flask's request-scoped ``g`` object so repeated
    calls within one request hit the database only once.
    """
    if "current_user" in g:
        return g.current_user
    user_id = session.get(_USER_SESSION_KEY)
    user: Optional[User] = None
    if user_id is not None:
        user = db.session.get(User, user_id)
        # Defensively log out deactivated or deleted accounts.
        if user is not None and not user.is_active:
            user = None
    g.current_user = user
    return user


# ---------------------------------------------------------------------------
# Access-control decorators
# ---------------------------------------------------------------------------
def login_required(view: Callable) -> Callable:
    """Redirect anonymous users to the login page, preserving ``next``."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("auth.login", next=request.full_path))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles: Role) -> Callable:
    """Restrict a view to users whose role is in ``roles`` (server-side check).

    Anonymous users are sent to login; authenticated users without a matching
    role get a 403. This is the authoritative gate -- the UI merely hides links.
    """

    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                flash("Please sign in to continue.", "info")
                return redirect(url_for("auth.login", next=request.full_path))
            if user.role not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
