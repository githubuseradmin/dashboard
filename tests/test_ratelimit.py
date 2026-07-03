"""Unit tests for the login rate-limiting throttle.

Pure, deterministic tests: a fake clock is injected so time advances only when
the test says so. No Flask app, database or network is involved. Standard
library ``unittest`` only, matching the rest of the suite.
"""

from __future__ import annotations

import os
import sys
import unittest

# Make the project root importable when run directly (python tests/...).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ratelimit import LoginThrottle


class _FakeClock:
    """A manually-advanced monotonic clock for deterministic tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class LoginThrottleTests(unittest.TestCase):
    def setUp(self):
        self.clock = _FakeClock()
        self.throttle = LoginThrottle(
            max_attempts=3, lockout_seconds=60, clock=self.clock
        )

    def test_new_key_is_not_locked(self):
        self.assertFalse(self.throttle.is_locked("alice@example.com"))
        self.assertEqual(self.throttle.seconds_remaining("alice@example.com"), 0)

    def test_locks_after_max_failures(self):
        key = "alice@example.com"
        for _ in range(2):
            self.throttle.record_failure(key)
        # Below the threshold: still open.
        self.assertFalse(self.throttle.is_locked(key))
        # The failure that reaches the threshold trips the lock.
        self.throttle.record_failure(key)
        self.assertTrue(self.throttle.is_locked(key))

    def test_seconds_remaining_counts_down_and_rounds_up(self):
        key = "bob"
        for _ in range(3):
            self.throttle.record_failure(key)
        # Full window remaining right after locking.
        self.assertEqual(self.throttle.seconds_remaining(key), 60)
        # A partial second must round up, never report a misleading 0.
        self.clock.advance(59.5)
        self.assertEqual(self.throttle.seconds_remaining(key), 1)

    def test_unlocks_after_window_elapses(self):
        key = "carol"
        for _ in range(3):
            self.throttle.record_failure(key)
        self.assertTrue(self.throttle.is_locked(key))
        # Advance just past the lockout window: the oldest failure ages out.
        self.clock.advance(61)
        self.assertFalse(self.throttle.is_locked(key))
        self.assertEqual(self.throttle.seconds_remaining(key), 0)

    def test_sliding_window_drops_stale_failures(self):
        key = "dave"
        # Two failures, then let them age past the window.
        self.throttle.record_failure(key)
        self.throttle.record_failure(key)
        self.clock.advance(61)
        # Stale failures should not count toward the threshold anymore.
        self.throttle.record_failure(key)
        self.throttle.record_failure(key)
        self.assertFalse(self.throttle.is_locked(key))
        self.throttle.record_failure(key)
        self.assertTrue(self.throttle.is_locked(key))

    def test_clear_resets_a_key(self):
        key = "erin"
        for _ in range(3):
            self.throttle.record_failure(key)
        self.assertTrue(self.throttle.is_locked(key))
        self.throttle.clear(key)
        self.assertFalse(self.throttle.is_locked(key))
        self.assertEqual(self.throttle.seconds_remaining(key), 0)

    def test_clear_is_safe_on_unknown_key(self):
        # Must not raise even if the key was never seen.
        self.throttle.clear("never-seen")
        self.assertFalse(self.throttle.is_locked("never-seen"))

    def test_keys_are_independent(self):
        for _ in range(3):
            self.throttle.record_failure("locked-user")
        self.throttle.record_failure("other-user")
        self.assertTrue(self.throttle.is_locked("locked-user"))
        self.assertFalse(self.throttle.is_locked("other-user"))

    def test_reset_clears_all_state(self):
        self.throttle.record_failure("a")
        self.throttle.record_failure("a")
        self.throttle.record_failure("a")
        self.throttle.record_failure("b")
        self.throttle.reset()
        self.assertFalse(self.throttle.is_locked("a"))
        self.assertEqual(self.throttle.seconds_remaining("b"), 0)

    def test_invalid_construction_is_rejected(self):
        with self.assertRaises(ValueError):
            LoginThrottle(max_attempts=0)
        with self.assertRaises(ValueError):
            LoginThrottle(lockout_seconds=0)

    def test_default_clock_is_time_time(self):
        # Real clock: a fresh key is open and stays consistent across calls.
        throttle = LoginThrottle(max_attempts=1, lockout_seconds=300)
        self.assertFalse(throttle.is_locked("real-clock-key"))
        throttle.record_failure("real-clock-key")
        self.assertTrue(throttle.is_locked("real-clock-key"))
        self.assertGreater(throttle.seconds_remaining("real-clock-key"), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
