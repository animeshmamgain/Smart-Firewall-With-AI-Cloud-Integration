"""
event_consumer.py — Tails the AI's events.jsonl in a background thread,
and checks heartbeat for true liveness.
"""

import json
import threading
import time
from pathlib import Path

from config import EVENTS_FILE, EVENT_POLL_INTERVAL, SHARED_DIR


HEARTBEAT_FILE = SHARED_DIR / "heartbeat.txt"
HEARTBEAT_TIMEOUT = 8.0   # seconds; older than this = stale


class EventConsumer:
    """Background tailer for the JSON-lines event stream."""

    def __init__(self, on_event, path: Path = EVENTS_FILE):
        self._on_event = on_event
        self._path     = path
        self._running  = False
        self._thread   = None

    # ── Public API ─────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def liveness(self) -> str:
        """
        Return one of: "live", "stale", "down".
          live  = heartbeat <= 8s old
          stale = heartbeat 8–30s old
          down  = heartbeat missing or >30s old
        """
        if not HEARTBEAT_FILE.exists():
            return "down"
        try:
            ts = float(HEARTBEAT_FILE.read_text().strip())
        except Exception:
            return "down"
        age = time.time() - ts
        if age <= HEARTBEAT_TIMEOUT:
            return "live"
        if age <= 30:
            return "stale"
        return "down"

    def heartbeat_age(self) -> float:
        """Seconds since last heartbeat, or -1 if none."""
        if not HEARTBEAT_FILE.exists():
            return -1
        try:
            ts = float(HEARTBEAT_FILE.read_text().strip())
            return time.time() - ts
        except Exception:
            return -1

    # ── Background ─────────────────────────────────────────────────

    def _tail_loop(self):
        position = 0
        # Start at end of file so we don't replay old events on launch
        try:
            if self._path.exists():
                position = self._path.stat().st_size
        except Exception:
            pass

        while self._running:
            try:
                if not self._path.exists():
                    time.sleep(EVENT_POLL_INTERVAL)
                    continue

                size = self._path.stat().st_size
                if size < position:
                    position = 0   # file truncated, reset

                if size > position:
                    with open(self._path, "r") as f:
                        f.seek(position)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            self._dispatch(line)
                        position = f.tell()

            except Exception as e:
                print(f"[event_consumer] error: {e}")

            time.sleep(EVENT_POLL_INTERVAL)

    def _dispatch(self, line: str):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        try:
            self._on_event(event)
        except Exception as e:
            print(f"[event_consumer] handler error: {e}")
