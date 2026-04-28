"""
detector_runner.py — Manages the AI detector as a subprocess.

The agent owns the detector's lifecycle: starts it, captures its log output,
detects crashes, and shuts it down cleanly.
"""

import subprocess
import threading
import time
import os
import signal
from collections import deque
from pathlib import Path

from config import PROJECT_DIR


class DetectorRunner:
    """Spawn and supervise the AI detector script."""

    DETECTOR_SCRIPT = PROJECT_DIR / "ai" / "scripts" / "detector.py"
    PYTHON_BIN      = PROJECT_DIR / "venv" / "bin" / "python3"
    LOG_BUFFER_MAX  = 200

    def __init__(self, on_log=None):
        self._proc = None
        self._reader_thread = None
        self._on_log = on_log
        self._log_buffer = deque(maxlen=self.LOG_BUFFER_MAX)
        self._lock = threading.Lock()

    # ── Public API ─────────────────────────────────────────────────

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> str:
        """Start the detector. Returns status message."""
        if self.is_running():
            return "Detector already running"

        if not self.DETECTOR_SCRIPT.exists():
            return f"Detector script not found at {self.DETECTOR_SCRIPT}"
        if not self.PYTHON_BIN.exists():
            return f"venv Python not found at {self.PYTHON_BIN}"

        try:
            # Detector inherits root from the agent (we run as sudo).
            # -u for unbuffered output so we see logs in real time.
            self._proc = subprocess.Popen(
                [str(self.PYTHON_BIN), "-u", str(self.DETECTOR_SCRIPT)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
            )
            self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
            self._reader_thread.start()
            return f"Detector started (PID {self._proc.pid})"
        except Exception as e:
            return f"Failed to start detector: {e}"

    def stop(self) -> str:
        """Stop the detector cleanly (SIGINT first, then SIGKILL)."""
        if not self.is_running():
            return "Detector not running"

        pid = self._proc.pid
        try:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=2)
        except Exception as e:
            return f"Error stopping detector: {e}"
        finally:
            self._proc = None

        return f"Detector stopped (was PID {pid})"

    def get_log_lines(self) -> list:
        with self._lock:
            return list(self._log_buffer)

    def get_pid(self):
        return self._proc.pid if self.is_running() else None

    # ── Internal ───────────────────────────────────────────────────

    def _read_loop(self):
        """Read detector stdout line by line, buffer it."""
        try:
            for line in self._proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                with self._lock:
                    self._log_buffer.append(line)
                if self._on_log:
                    try:
                        self._on_log(line)
                    except Exception:
                        pass
        except Exception:
            pass
