"""Login rate-limiting: an in-memory sliding-window throttle with lockout.

This module is deliberately dependency-free and side-effect-free so it can be
unit-tested in isolation with a deterministic, injected clock. The throttle
tracks recent *failed* attempts per key (a lowercased identifier such as an
email or username) inside a sliding window. Once too many failures accumulate
the key is "locked" until the oldest counted failure ages out of the window.

Design notes:
* Pure: no Flask, no database, no logging. Callers own those concerns.
* Injectable clock: ``LoginThrottle(clock=...)`` lets tests advance time
  explicitly; the default is ``time.monotonic`` is intentionally *not* used --
  wall-clock ``time.time`` matches the human-facing "try again in N seconds".
* Keys are treated as opaque strings; the caller is responsible for
  normalising them (lowercasing/stripping) consistently.

LIMITATION: the state lives in a plain dict in this process's memory. A
module-level singleton (see ``throttle`` below) is fine for this single-process
development app, but it does NOT survive a restart and is NOT shared across
multiple worker processes or hosts. A production deployment behind several
workers should back this with a shared store (e.g. Redis) instead.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict


class LoginThrottle:
    """Sliding-window failed-attempt counter with a temporary lockout.

    A key becomes locked once it accumulates ``max_attempts`` failures within
    the trailing ``lockout_seconds`` window. It automatically unlocks when the
    oldest counted failure drops out of that window, so no background cleanup
    task is required.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        lockout_seconds: int = 300,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if lockout_seconds < 1:
            raise ValueError("lockout_seconds must be >= 1")
        self.max_attempts = int(max_attempts)
        self.lockout_seconds = int(lockout_seconds)
        self._clock = clock
        # key -> timestamps of recent failures (oldest first).
        self._failures: Dict[str, Deque[float]] = defaultdict(deque)
        # Guards the shared dict; cheap, and keeps the singleton usable under
        # a threaded dev server without corrupting the deques.
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> Deque[float]:
        """Drop failures older than the window and return the live deque."""
        window_start = now - self.lockout_seconds
        stamps = self._failures[key]
        while stamps and stamps[0] <= window_start:
            stamps.popleft()
        if not stamps:
            # Avoid unbounded growth of empty entries in the backing dict.
            self._failures.pop(key, None)
        return stamps

    def is_locked(self, key: str) -> bool:
        """Return ``True`` while ``key`` has reached the failure threshold."""
        return self.seconds_remaining(key) > 0

    def seconds_remaining(self, key: str) -> int:
        """Seconds until ``key`` unlocks, or ``0`` if it is not locked.

        The value is rounded *up* so a partial second still reads as "1 more
        second" rather than misleading the user with "0".
        """
        now = self._clock()
        with self._lock:
            stamps = self._prune(key, now)
            if len(stamps) < self.max_attempts:
                return 0
            # Locked: the window clears when the oldest failure ages out.
            unlock_at = stamps[0] + self.lockout_seconds
            remaining = unlock_at - now
        if remaining <= 0:
            return 0
        return int(remaining) + (1 if remaining % 1 else 0)

    def record_failure(self, key: str) -> None:
        """Record one failed attempt for ``key`` at the current time."""
        now = self._clock()
        with self._lock:
            stamps = self._prune(key, now)
            stamps.append(now)
            # ``_prune`` may have removed the entry; ensure it is stored again.
            self._failures[key] = stamps

    def clear(self, key: str) -> None:
        """Forget all recorded failures for ``key`` (call on a success)."""
        with self._lock:
            self._failures.pop(key, None)

    def reset(self) -> None:
        """Drop all state. Intended for tests and admin tooling."""
        with self._lock:
            self._failures.clear()


# Module-level singleton shared by the auth blueprint. Fine for this
# single-process dev app; see the LIMITATION note in the module docstring for
# why a multi-process production deployment needs a shared backing store.
throttle = LoginThrottle()


def configure_from_app(config) -> None:
    """Point the module-level ``throttle`` at the app's configured limits.

    Called once from the application factory so ``LOGIN_MAX_ATTEMPTS`` /
    ``LOGIN_LOCKOUT_SECONDS`` from config drive the live singleton. State is
    reset so a reconfiguration never leaves stale counters behind.
    """
    global throttle
    throttle = LoginThrottle(
        max_attempts=int(config.get("LOGIN_MAX_ATTEMPTS", 5)),
        lockout_seconds=int(config.get("LOGIN_LOCKOUT_SECONDS", 300)),
    )
