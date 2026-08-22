import threading
import time

import pytest

from aeptf.core.concurrency import TargetBusyError, TargetCooldownError, TargetGovernor


def test_acquire_blocks_concurrent_access_to_same_target():
    governor = TargetGovernor()
    started = threading.Event()
    release = threading.Event()
    result = {}

    def hold_lock():
        with governor.acquire("1.2.3.4"):
            started.set()
            release.wait(timeout=2)

    t = threading.Thread(target=hold_lock)
    t.start()
    started.wait(timeout=2)

    try:
        with pytest.raises(TargetBusyError):
            with governor.acquire("1.2.3.4"):
                pass
    finally:
        release.set()
        t.join(timeout=2)


def test_acquire_allows_different_targets_concurrently():
    governor = TargetGovernor()
    with governor.acquire("1.2.3.4"):
        with governor.acquire("5.6.7.8"):
            pass  # must not raise


def test_cooldown_blocks_immediate_rerun():
    governor = TargetGovernor()
    with governor.acquire("1.2.3.4", min_seconds=60):
        pass
    with pytest.raises(TargetCooldownError):
        with governor.acquire("1.2.3.4", min_seconds=60):
            pass


def test_cooldown_zero_disables_check():
    governor = TargetGovernor()
    with governor.acquire("1.2.3.4", min_seconds=0):
        pass
    with governor.acquire("1.2.3.4", min_seconds=0):
        pass  # must not raise
