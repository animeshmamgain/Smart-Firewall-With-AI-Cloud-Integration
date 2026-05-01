"""
alert_store.py — In-memory alert state separate from the database.

The database is for persistence and stats; this is for live UI state.
Three logical buckets:
  - recent:  every alert ever received this session, capped to MAX
  - pending: alerts in manual mode waiting for user approval
  - dismissed/approved are removed from pending and labeled in recent

Thread-safe.
"""

import threading
import time
import uuid
from collections import deque

from config import MAX_RECENT_ALERTS


class AlertStore:
    """Holds alert state for the GUI."""

    def __init__(self):
        self._lock = threading.Lock()
        self._recent  = deque(maxlen=MAX_RECENT_ALERTS)
        self._pending = {}      # alert_id -> alert_record
        self._next_id = 0

    # ── Adding alerts ──────────────────────────────────────────────

    def add(self, event: dict, status: str) -> str:
        """
        Add a new alert. status ∈ {"BLOCKED", "EXISTING", "PENDING"}.
        Returns the alert_id (useful for pending alerts).
        """
        with self._lock:
            self._next_id += 1
            alert_id = f"a{self._next_id:06d}"
            record = {
                "id":     alert_id,
                "ts":     time.strftime("%H:%M:%S"),
                "ts_raw": time.time(),
                "event":  event,
                "status": status,
            }
            self._recent.appendleft(record)
            if status == "PENDING":
                self._pending[alert_id] = record
            return alert_id

    # ── Pending queue ──────────────────────────────────────────────

    def list_pending(self) -> list:
        with self._lock:
            return list(self._pending.values())

    def approve(self, alert_id: str) -> dict:
        """Move an alert out of pending and mark it APPROVED. Returns the record or None."""
        with self._lock:
            record = self._pending.pop(alert_id, None)
            if record:
                record["status"] = "APPROVED"
            return record

    def dismiss(self, alert_id: str) -> dict:
        """Move an alert out of pending and mark it DISMISSED."""
        with self._lock:
            record = self._pending.pop(alert_id, None)
            if record:
                record["status"] = "DISMISSED"
            return record

    def clear_pending(self) -> int:
        """Remove all pending. Returns count removed."""
        with self._lock:
            n = len(self._pending)
            self._pending.clear()
            return n

    # ── Recent feed ────────────────────────────────────────────────

    def list_recent(self) -> list:
        with self._lock:
            return list(self._recent)

    def find(self, alert_id: str) -> dict:
        """Find an alert by ID anywhere in recent."""
        with self._lock:
            for r in self._recent:
                if r["id"] == alert_id:
                    return r
            return None

    def clear_all(self):
        """Wipe everything from memory."""
        with self._lock:
            self._recent.clear()
            self._pending.clear()
