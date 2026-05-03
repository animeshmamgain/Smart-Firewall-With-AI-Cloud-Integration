"""
detector_runner.py — Manages the AI detector as a subprocess.
"""

import subprocess
import threading
import signal
from collections import deque
from pathlib import Path
import sys

from config import PROJECT_DIR
from logger import get_logger

log = get_logger("detector_runner")


class DetectorRunner:
    DETECTOR_SCRIPT = PROJECT_DIR / "ai" / "scripts" / "detector.py"
    PYTHON_BIN      = Path(sys.executable)
    LOG_BUFFER_MAX  = 200

    def __init__(self, on_log=None):
        self._proc          = None
        self._reader_thread = None
        self._on_log        = on_log
        self._log_buffer    = deque(maxlen=self.LOG_BUFFER_MAX)
        self._lock          = threading.Lock()

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> str:
        if self.is_running():
            log.warning("Detector start requested but already running")
            return "Detector already running"
        if not self.DETECTOR_SCRIPT.exists():
            msg = f"Detector script not found at {self.DETECTOR_SCRIPT}"
            log.error(msg); return msg
        if not self.PYTHON_BIN.exists():
            msg = f"venv Python not found at {self.PYTHON_BIN}"
            log.error(msg); return msg
        try:
            self._proc = subprocess.Popen(
                [str(self.PYTHON_BIN), "-u", str(self.DETECTOR_SCRIPT)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
            )
            self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
            self._reader_thread.start()
            msg = f"Detector started (PID {self._proc.pid})"
            log.info(msg); return msg
        except Exception as e:
            log.error(f"Failed to start detector subprocess: {e}")
            return f"Failed to start detector: {e}"

    def stop(self) -> str:
        if not self.is_running():
            return "Detector not running"
        pid = self._proc.pid
        try:
            log.info(f"Sending SIGINT to detector (PID {pid})")
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=4)
                log.info(f"Detector (PID {pid}) exited cleanly")
            except subprocess.TimeoutExpired:
                log.warning(f"Detector (PID {pid}) did not exit — sending SIGKILL")
                self._proc.kill()
                self._proc.wait(timeout=2)
        except Exception as e:
            log.error(f"Error stopping detector (PID {pid}): {e}")
            return f"Error stopping detector: {e}"
        finally:
            self._proc = None
        return f"Detector stopped (was PID {pid})"

    def get_log_lines(self) -> list:
        with self._lock:
            return list(self._log_buffer)

    def get_pid(self):
        return self._proc.pid if self.is_running() else None

    def _read_loop(self):
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
                    except Exception as e:
                        log.warning(f"on_log callback raised: {e}")
        except Exception as e:
            log.error(f"Detector stdout reader crashed: {e}")
        if self._proc is not None:
            rc = self._proc.poll()
            if rc is not None and rc != 0:
                log.error(f"Detector subprocess exited with code {rc}")
