"""Telegram integration helpers (standard library only).

This module is the single place that knows how to talk to Telegram:

* sign / verify stateless account-link tokens (used in the bot deep link),
* validate Telegram Mini App ``initData`` (HMAC-SHA256, per Telegram's spec),
* generate sign-in approval codes/tokens,
* send messages through the Bot HTTP API.

It deliberately avoids third-party packages (no ``requests``, no aiogram) so the
Flask side stays dependency-light: outbound messages are plain ``urllib`` POSTs
and all crypto is ``hmac``/``hashlib``. The separate bot process (``bot/``) may
import these same helpers, passing the token/secret explicitly so they work with
no Flask application context.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from typing import Optional

_API_BASE = "https://api.telegram.org"


# ---------------------------------------------------------------------------
# Config access (works with or without a Flask application context)
# ---------------------------------------------------------------------------
def _config(key: str, default: str = "") -> str:
    """Read a setting from Flask config when available, else the environment."""
    try:
        from flask import current_app, has_app_context

        if has_app_context():
            return current_app.config.get(key, os.environ.get(key, default))
    except Exception:  # pragma: no cover - flask always importable here
        pass
    return os.environ.get(key, default)


def bot_token() -> str:
    return _config("TELEGRAM_BOT_TOKEN")


def bot_username() -> str:
    """The bot's @username without the leading @ (for deep links)."""
    return _config("TELEGRAM_BOT_USERNAME").lstrip("@")


def webapp_url() -> str:
    return _config("TELEGRAM_WEBAPP_URL")


def is_configured() -> bool:
    """True when a bot token is present, so Telegram features can be used."""
    return bool(bot_token())


def _secret() -> str:
    return _config("SECRET_KEY", "dev-insecure-change-me")


# ---------------------------------------------------------------------------
# Sign-in approval codes / tokens
# ---------------------------------------------------------------------------
def gen_code() -> str:
    """A 6-digit numeric code (zero-padded) for the login-approval fallback."""
    return f"{secrets.randbelow(1_000_000):06d}"


def gen_request_token() -> str:
    """A short opaque token for a LoginRequest (fits Telegram callback_data)."""
    return secrets.token_urlsafe(12)


# ---------------------------------------------------------------------------
# Stateless, signed account-link tokens (used in the t.me/<bot>?start=<token>)
# ---------------------------------------------------------------------------
def make_link_token(user_id: int, secret: Optional[str] = None) -> str:
    """Sign ``user_id`` into a compact, URL-safe, time-stamped link token.

    Stateless on purpose: the bot can verify it with the shared SECRET_KEY and
    no database round trip. Kept short to satisfy Telegram's 64-char start-param
    limit (allowed chars: A-Z a-z 0-9 _ -, which base64url provides).
    """
    secret = secret or _secret()
    payload = f"{int(user_id)}.{int(time.time())}"
    sig = _sign(payload, secret)
    raw = f"{payload}.{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_link_token(
    token: str, max_age: int = 600, secret: Optional[str] = None
) -> Optional[int]:
    """Verify a link token and return the user id, or ``None`` if invalid/expired."""
    secret = secret or _secret()
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        user_id_s, ts_s, sig = raw.rsplit(".", 2)
        payload = f"{user_id_s}.{ts_s}"
        if not hmac.compare_digest(_sign(payload, secret), sig):
            return None
        if max_age and (time.time() - int(ts_s)) > max_age:
            return None
        return int(user_id_s)
    except Exception:
        return None


def _sign(payload: str, secret: str) -> str:
    """Truncated HMAC-SHA256 hex signature (64 bits is plenty for a 10-min token)."""
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Telegram Mini App initData validation (HMAC-SHA256 per the official spec)
# ---------------------------------------------------------------------------
def validate_init_data(
    init_data: str, token: Optional[str] = None, max_age: int = 86_400
) -> Optional[dict]:
    """Validate a Mini App ``initData`` string and return its parsed fields.

    Returns ``{"params": {...}, "user": {...}|None}`` when the signature checks
    out, else ``None``. ``max_age`` (seconds) rejects stale payloads; pass 0 to
    skip the freshness check (useful in unit tests).
    """
    token = token or bot_token()
    if not init_data or not token:
        return None
    try:
        params = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
    except Exception:
        return None

    received_hash = params.pop("hash", None)
    if not received_hash:
        return None

    check_string = "\n".join(f"{k}={params[k]}" for k in sorted(params))
    secret_key = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    computed = hmac.new(
        secret_key, check_string.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(computed, received_hash):
        return None

    if max_age:
        try:
            auth_date = int(params.get("auth_date", "0"))
            if auth_date and (time.time() - auth_date) > max_age:
                return None
        except (TypeError, ValueError):
            return None

    user = None
    if "user" in params:
        try:
            user = json.loads(params["user"])
        except (TypeError, ValueError):
            user = None
    return {"params": params, "user": user}


# ---------------------------------------------------------------------------
# Outbound messaging (Bot HTTP API via urllib; no third-party dependency)
# ---------------------------------------------------------------------------
def login_keyboard(token: str) -> dict:
    """Inline keyboard with Confirm / Deny buttons for a sign-in request."""
    return {
        "inline_keyboard": [
            [
                {"text": "✅ Confirm", "callback_data": f"tgl:a:{token}"},
                {"text": "❌ Deny", "callback_data": f"tgl:d:{token}"},
            ]
        ]
    }


def send_message(
    chat_id: int,
    text: str,
    reply_markup: Optional[dict] = None,
    token: Optional[str] = None,
    timeout: float = 8.0,
) -> bool:
    """Send a message via the Bot API. Returns True on success, never raises.

    Failures (no token configured, network error, Telegram error) are swallowed
    and reported as ``False`` so a missing/unreachable bot can never break a web
    request.
    """
    token = token or bot_token()
    if not token or not chat_id:
        return False
    payload: dict = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup is not None:
        payload["reply_markup"] = json.dumps(reply_markup)

    data = urllib.parse.urlencode(payload).encode()
    url = f"{_API_BASE}/bot{token}/sendMessage"
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode())
            return bool(body.get("ok"))
    except Exception:
        return False


def notify(user, text: str) -> bool:
    """Send ``text`` to a user's linked Telegram if they opted in to notices."""
    if user is None or not getattr(user, "telegram_id", None):
        return False
    if not getattr(user, "telegram_notify", False):
        return False
    return send_message(user.telegram_id, text)
