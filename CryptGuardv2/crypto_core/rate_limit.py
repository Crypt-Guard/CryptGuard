"""
Thread-safe rate limiting utilities for CryptGuard v2.

Provides per-identifier failure counting with lockout windows.
"""

from __future__ import annotations

import threading
import time

# Module defaults (can be overridden per call)
_MAX_FAILURES_DEFAULT: int = 5
_LOCKOUT_TIME_DEFAULT: float = 300.0  # seconds

# Internal mutable state
_failure_counts: dict[str, int] = {}
_last_attempt: dict[str, float] = {}

# Single process-wide lock for thread safety
_lock = threading.Lock()


def check_allowed(
    identifier: str = "default",
    max_failures: int | None = None,
    lockout_time: float | None = None,
) -> bool:
    """
    Return True if the operation identified by `identifier` is currently allowed.

    A caller should call `register_failure(identifier)` after a failed attempt,
    and `register_success(identifier)` (or `reset(identifier)`) after a success.

    Lockout semantics:
      - Before reaching `max_failures`, always allowed (True).
      - Once failures >= max_failures, deny (False) until `lockout_time` seconds
        have passed since the last failure. After that window, the state is reset
        and the next call will be allowed again.
    """
    mf = _MAX_FAILURES_DEFAULT if max_failures is None else int(max_failures)
    lt = _LOCKOUT_TIME_DEFAULT if lockout_time is None else float(lockout_time)

    now = time.time()
    with _lock:
        fails = _failure_counts.get(identifier, 0)
        last = _last_attempt.get(identifier, 0.0)

        if fails < mf:
            return True

        # In lockout window?
        remaining = (last + lt) - now
        if remaining > 0:
            return False

        # Lockout window expired -> reset state and allow again
        _failure_counts.pop(identifier, None)
        _last_attempt.pop(identifier, None)
        return True


def get_lockout_remaining(
    identifier: str,
    max_failures: int | None = None,
    lockout_time: float | None = None,
) -> float:
    """
    Return seconds remaining in the lockout window for `identifier`.
    Returns 0 when not locked out.
    """
    mf = _MAX_FAILURES_DEFAULT if max_failures is None else int(max_failures)
    lt = _LOCKOUT_TIME_DEFAULT if lockout_time is None else float(lockout_time)

    now = time.time()
    with _lock:
        fails = _failure_counts.get(identifier, 0)
        if fails < mf:
            return 0.0
        last = _last_attempt.get(identifier, 0.0)
        remaining = (last + lt) - now
        return max(0.0, remaining)


def register_failure(identifier: str = "default") -> None:
    """
    Record a failed attempt for `identifier`.
    """
    now = time.time()
    with _lock:
        _failure_counts[identifier] = _failure_counts.get(identifier, 0) + 1
        _last_attempt[identifier] = now


def register_success(identifier: str = "default") -> None:
    """
    Clear failure/lockout state for `identifier` (i.e., after a successful attempt).
    """
    with _lock:
        _failure_counts.pop(identifier, None)
        _last_attempt.pop(identifier, None)


# Backwards-compatible alias expected elsewhere in the codebase
reset = register_success


def get_failure_count(identifier: str = "default") -> int:
    """
    Return current failure count for `identifier`.
    """
    with _lock:
        return _failure_counts.get(identifier, 0)


__all__ = [
    "check_allowed",
    "register_failure",
    "register_success",
    "reset",
    "get_failure_count",
    "get_lockout_remaining",
]
