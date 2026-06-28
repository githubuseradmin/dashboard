"""Tests for the Telegram integration helpers and endpoints.

Pure helpers (initData HMAC, signed link tokens, codes) are tested in isolation;
a couple of light integration tests cover the Mini App page and the API's
unauthenticated path. Standard-library ``unittest`` only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import unittest
import urllib.parse

from app import create_app, telegram as tg
from app.extensions import db

_SECRET = "unit-test-secret"
_BOT_TOKEN = "123456:TEST-BOT-TOKEN"


def _build_init_data(token: str, user: dict, auth_date: int | None = None) -> str:
    """Construct a correctly-signed Telegram WebApp initData string."""
    params = {
        "auth_date": str(auth_date if auth_date is not None else int(time.time())),
        "query_id": "AAEjabc123",
        "user": json.dumps(user, separators=(",", ":")),
    }
    check_string = "\n".join(f"{k}={params[k]}" for k in sorted(params))
    secret_key = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    params["hash"] = hmac.new(
        secret_key, check_string.encode(), hashlib.sha256
    ).hexdigest()
    return urllib.parse.urlencode(params)


class LinkTokenTests(unittest.TestCase):
    def test_round_trip(self):
        token = tg.make_link_token(42, secret=_SECRET)
        self.assertEqual(tg.parse_link_token(token, secret=_SECRET), 42)

    def test_link_token_is_url_safe_and_short(self):
        token = tg.make_link_token(123456789, secret=_SECRET)
        # Telegram start params allow [A-Za-z0-9_-] and max 64 chars.
        self.assertLessEqual(len(token), 64)
        self.assertRegex(token, r"^[A-Za-z0-9_-]+$")

    def test_wrong_secret_is_rejected(self):
        token = tg.make_link_token(7, secret=_SECRET)
        self.assertIsNone(tg.parse_link_token(token, secret="other-secret"))

    def test_tampered_token_is_rejected(self):
        token = tg.make_link_token(7, secret=_SECRET)
        tampered = ("A" if token[0] != "A" else "B") + token[1:]
        self.assertIsNone(tg.parse_link_token(tampered, secret=_SECRET))

    def test_garbage_returns_none(self):
        self.assertIsNone(tg.parse_link_token("not-a-token", secret=_SECRET))
        self.assertIsNone(tg.parse_link_token("", secret=_SECRET))

    def test_expired_token_is_rejected(self):
        # Hand-build a token with an old timestamp but a valid signature.
        old_ts = int(time.time()) - 10_000
        payload = f"5.{old_ts}"
        sig = tg._sign(payload, _SECRET)
        raw = f"{payload}.{sig}".encode()
        token = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertIsNone(tg.parse_link_token(token, max_age=600, secret=_SECRET))
        # With the freshness check disabled it still parses.
        self.assertEqual(tg.parse_link_token(token, max_age=0, secret=_SECRET), 5)


class InitDataTests(unittest.TestCase):
    def test_valid_init_data(self):
        init = _build_init_data(_BOT_TOKEN, {"id": 99, "first_name": "Ada"})
        parsed = tg.validate_init_data(init, token=_BOT_TOKEN, max_age=0)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["user"]["id"], 99)

    def test_tampered_hash_is_rejected(self):
        init = _build_init_data(_BOT_TOKEN, {"id": 99})
        tampered = init.replace(init.split("hash=")[1], "deadbeef")
        self.assertIsNone(tg.validate_init_data(tampered, token=_BOT_TOKEN, max_age=0))

    def test_wrong_bot_token_is_rejected(self):
        init = _build_init_data(_BOT_TOKEN, {"id": 99})
        self.assertIsNone(
            tg.validate_init_data(init, token="999:WRONG", max_age=0)
        )

    def test_missing_hash_and_empty_are_rejected(self):
        self.assertIsNone(tg.validate_init_data("", token=_BOT_TOKEN, max_age=0))
        self.assertIsNone(
            tg.validate_init_data("auth_date=1&user=%7B%7D", token=_BOT_TOKEN, max_age=0)
        )

    def test_stale_init_data_is_rejected(self):
        init = _build_init_data(
            _BOT_TOKEN, {"id": 1}, auth_date=int(time.time()) - 100_000
        )
        self.assertIsNone(
            tg.validate_init_data(init, token=_BOT_TOKEN, max_age=3600)
        )


class CodeTests(unittest.TestCase):
    def test_gen_code_is_six_digits(self):
        for _ in range(50):
            code = tg.gen_code()
            self.assertEqual(len(code), 6)
            self.assertTrue(code.isdigit())

    def test_request_token_is_url_safe(self):
        self.assertRegex(tg.gen_request_token(), r"^[A-Za-z0-9_-]+$")


class NotifyTests(unittest.TestCase):
    class _U:
        def __init__(self, tid, notify):
            self.telegram_id = tid
            self.telegram_notify = notify

    def test_notify_noops_without_link_or_optout(self):
        # No network is attempted in any of these cases.
        self.assertFalse(tg.notify(None, "x"))
        self.assertFalse(tg.notify(self._U(None, True), "x"))
        self.assertFalse(tg.notify(self._U(123, False), "x"))


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        with self.app.app_context():
            db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()

    def test_mini_app_page_renders(self):
        resp = self.client.get("/tg/app")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"telegram-web-app.js", resp.data)

    def test_api_me_requires_valid_init_data(self):
        # No initData -> unauthorized, and the CSRF guard must not block it.
        resp = self.client.post("/api/telegram/me", json={"initData": ""})
        self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
