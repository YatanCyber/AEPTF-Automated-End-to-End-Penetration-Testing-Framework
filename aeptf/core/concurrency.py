"""Per-target concurrency control.

Two independent protections, both keyed by the normalized target string:

1. A lock, so two runs can never execute against the same target at the
   same instant, whether they arrived from the sync API, the async job
   queue, or the CLI in the same process.
2. An optional cooldown (`safety.min_seconds_between_runs`), so a target
   can't be re-run more often than the operator allows even when calls
   are sequential rather than concurrent.

Neither of these is a substitute for the approved_targets allowlist --
they bound *rate*, not *authorization*.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Iterator


class TargetBusyError(RuntimeError):
    """Raised when a target already has a run in progress."""


class TargetCooldownError(RuntimeError):
    """Raised when a target was run too recently."""


class TargetGovernor:
    def __init__(self) -> None:
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._last_run_finished: dict[str, float] = {}
        self._last_run_guard = threading.Lock()

    def _lock_for(self, target: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(target, threading.Lock())

    def check_cooldown(self, target: str, min_seconds: int) -> None:
        if min_seconds <= 0:
            return
        with self._last_run_guard:
            last = self._last_run_finished.get(target)
        if last is None:
            return
        elapsed = time.monotonic() - last
        if elapsed < min_seconds:
            raise TargetCooldownError(
                f"'{target}' was run {elapsed:.1f}s ago; "
                f"safety.min_seconds_between_runs requires {min_seconds}s between runs."
            )

    def mark_finished(self, target: str) -> None:
        with self._last_run_guard:
            self._last_run_finished[target] = time.monotonic()

    @contextmanager
    def acquire(self, target: str, min_seconds: int = 0) -> Iterator[None]:
        """Block a second concurrent run on `target`; raise if the
        cooldown hasn't elapsed. On exit, records when the run finished
        so the cooldown applies to the *next* run."""
        self.check_cooldown(target, min_seconds)
        lock = self._lock_for(target)
        if not lock.acquire(blocking=False):
            raise TargetBusyError(f"A run is already in progress against '{target}'.")
        try:
            yield
        finally:
            self.mark_finished(target)
            lock.release()


_governor_singleton = TargetGovernor()


def get_target_governor() -> TargetGovernor:
    return _governor_singleton
