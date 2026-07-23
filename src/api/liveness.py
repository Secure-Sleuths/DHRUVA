"""Alert-loop liveness heartbeat (WO-H10 Fix 3).

A minimal, thread-safe shared timestamp that the alert loop stamps once per
cycle and the ``/api/health`` probe reads to detect a dead/wedged loop thread.

Deliberately standalone (no orchestrator wiring, no DB) so it is trivially
importable from both ``main.py`` (writer) and the health route (reader), and so
the WO-H9 alert-loop refactor can relocate the ``record_cycle()`` call without
touching the API. Uses ``time.monotonic()`` for age math (immune to wall-clock
jumps) and also records a wall-clock ISO timestamp for human-readable display.
"""

import threading
import time as _time
from datetime import datetime, timezone
from typing import Optional

_lock = threading.Lock()
_last_cycle_monotonic: Optional[float] = None
_last_cycle_wall_iso: Optional[str] = None


def record_cycle() -> None:
    """Stamp 'the alert loop just completed a cycle'. Called each loop tick."""
    global _last_cycle_monotonic, _last_cycle_wall_iso
    with _lock:
        _last_cycle_monotonic = _time.monotonic()
        _last_cycle_wall_iso = datetime.now(timezone.utc).isoformat()


def last_cycle_age_seconds() -> Optional[float]:
    """Seconds since the last recorded cycle, or ``None`` if never recorded."""
    with _lock:
        if _last_cycle_monotonic is None:
            return None
        return max(0.0, _time.monotonic() - _last_cycle_monotonic)


def last_cycle_iso() -> Optional[str]:
    """Wall-clock ISO timestamp of the last recorded cycle, or ``None``."""
    with _lock:
        return _last_cycle_wall_iso


def reset() -> None:
    """Clear the heartbeat — test-support only."""
    global _last_cycle_monotonic, _last_cycle_wall_iso
    with _lock:
        _last_cycle_monotonic = None
        _last_cycle_wall_iso = None
