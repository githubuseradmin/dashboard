"""Unit tests for the security layer.

Covers password hashing/verification, TOTP enrolment/verification, CSRF token
handling and server-side ``role_required`` access control. The access-control
tests build a real (but in-memory) application so the decorators are exercised
end to end through Flask's request handling.
"""

from __future__ import annotations

import os
import sys
import unittest

# Make the project root importable when run directly (python tests/...).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp
from flask import Blueprint

from app import create_app
from app.extensions import db
from app.models import Role, User
from app.security import (
    generate_totp_secret,
    get_csrf_token,
    hash_password,
    login_user,
    role_required,
    validate_csrf,
    verify_password,
    verify_totp,
)


class PasswordHashingTests(unittest.TestCase):
    """bcrypt password hashing must be salted and verify correctly."""

    def test_hash_is_not_plaintext(self):
        hashed = hash_password("correct horse battery staple")
        self.assertNotIn("correct horse", hashed)
        self.assertTrue(hashed.startswith("$2"))  # bcrypt identifier

    def test_verify_accepts_correct_password(self):
        hashed = hash_password("s3cr3t-pass")
        self.assertTrue(verify_password("s3cr3t-pass", hashed))

    def test_verify_rejects_wrong_password(self):
        hashed = hash_password("s3cr3t-pass")
        self.assertFalse(verify_password("wrong-pass", hashed))

    def test_hashes_are_salted_and_unique(self):
        a = hash_password("same-password")
        b = hash_password("same-password")
        self.assertNotEqual(a, b)
        self.assertTrue(verify_password("same-password", a))
        self.assertTrue(verify_password("same-password", b))

    def test_verify_handles_malformed_hash(self):
        self.assertFalse(verify_password("anything", "not-a-real-hash"))
        self.assertFalse(verify_password("anything", ""))


class TotpTests(unittest.TestCase):
    """Time-based one-time password helpers."""

    def test_generated_secret_is_valid_base32(self):
        secret = generate_totp_secret()
        # A valid secret must produce a usable TOTP object and a current code.
        code = pyotp.TOTP(secret).now()
        self.assertEqual(len(code), 6)

    def test_verify_accepts_current_code(self):
        secret = generate_totp_secret()
        code = pyotp.TOTP(secret).now()
        self.assertTrue(verify_totp(secret, code))

    def test_verify_rejects_wrong_code(self):
        secret = generate_totp_secret()
        self.assertFalse(verify_totp(secret, "000000"))

    def test_verify_rejects_non_numeric_and_empty(self):
        secret = generate_totp_secret()
        self.assertFalse(verify_totp(secret, "abcdef"))
        self.assertFalse(verify_totp(secret, ""))
        self.assertFalse(verify_totp("", "123456"))

    def test_verify_tolerates_surrounding_whitespace(self):
        secret = generate_totp_secret()
        code = pyotp.TOTP(secret).now()
        self.assertTrue(verify_totp(secret, f"  {code} "))

    def test_qr_svg_is_embeddable_string(self):
        from app.security import totp_qr_svg

        secret = generate_totp_secret()
        svg = totp_qr_svg(secret, account_name="user@example.com", issuer="Dashboard")
        # Must be a string SVG fragment (no XML declaration) so it can be
        # dropped straight into a template with the |safe filter.
        self.assertIsInstance(svg, str)
        self.assertIn("<svg", svg)
        self.assertNotIn("<?xml", svg)
        # The plaintext secret must never appear in the rendered markup.
        self.assertNotIn(secret, svg)


class _AppTestCase(unittest.TestCase):
    """Base case that spins up a fresh in-memory app per test."""

    def setUp(self):
        self.app = create_app("testing")
        # Register lightweight protected routes used by the access-control tests.
        bp = Blueprint("probe", __name__)

        @bp.route("/staff-only")
        @role_required(Role.MODERATOR, Role.ADMIN)
        def staff_only():
            return "staff-area"

        @bp.route("/admin-only")
        @role_required(Role.ADMIN)
        def admin_only():
            return "admin-area"

        # Blueprints can only be registered before the first request.
        self.app.register_blueprint(bp)

        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def _make_user(self, role: Role, *, active: bool = True) -> User:
        user = User(
            email=f"{role.value}@example.com",
            username=role.value,
            display_name=role.label,
            password_hash=hash_password("password123"),
            role=role,
            is_active=active,
        )
        db.session.add(user)
        db.session.commit()
        return user

    def _client_logged_in_as(self, user: User):
        """Return a test client whose session is authenticated as ``user``."""
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = user.id
        return client


class RoleRequiredTests(_AppTestCase):
    """``role_required`` must enforce access on the server side."""

    def test_anonymous_is_redirected_to_login(self):
        client = self.app.test_client()
        resp = client.get("/staff-only")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_user_role_is_forbidden_from_staff_area(self):
        user = self._make_user(Role.USER)
        client = self._client_logged_in_as(user)
        resp = client.get("/staff-only")
        self.assertEqual(resp.status_code, 403)

    def test_moderator_can_access_staff_area(self):
        mod = self._make_user(Role.MODERATOR)
        client = self._client_logged_in_as(mod)
        resp = client.get("/staff-only")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"staff-area", resp.data)

    def test_moderator_is_forbidden_from_admin_only(self):
        mod = self._make_user(Role.MODERATOR)
        client = self._client_logged_in_as(mod)
        resp = client.get("/admin-only")
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_access_admin_only(self):
        admin = self._make_user(Role.ADMIN)
        client = self._client_logged_in_as(admin)
        resp = client.get("/admin-only")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"admin-area", resp.data)

    def test_deactivated_user_is_treated_as_logged_out(self):
        admin = self._make_user(Role.ADMIN, active=False)
        client = self._client_logged_in_as(admin)
        resp = client.get("/admin-only")
        # An inactive account resolves to "no current user" -> redirect to login.
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])


class CsrfTests(_AppTestCase):
    """The manual CSRF token must round-trip and reject mismatches."""

    def test_token_validates_against_itself(self):
        with self.app.test_request_context():
            token = get_csrf_token()
            self.assertTrue(validate_csrf(token))

    def test_token_rejects_wrong_value(self):
        with self.app.test_request_context():
            get_csrf_token()
            self.assertFalse(validate_csrf("bogus-token"))
            self.assertFalse(validate_csrf(None))


class LoginSessionTests(_AppTestCase):
    """High-level check that login state is reflected by current_user()."""

    def test_login_user_sets_session(self):
        user = self._make_user(Role.USER)
        with self.app.test_request_context():
            login_user(user)
            from app.security import current_user

            self.assertIsNotNone(current_user())
            self.assertEqual(current_user().id, user.id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
