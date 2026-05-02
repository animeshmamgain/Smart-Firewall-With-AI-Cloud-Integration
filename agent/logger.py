"""
logger.py — Shared logging setup for the SFW agent.

All modules import get_logger() from here. Logs go to:
  - Console (stdout) with colour-coded levels
  - agent/logs/agent.log (rotating, max 2 MB x 3 files)
"""

import logging
import logging.handlers
from pathlib import Path

LOG_DIR  = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "agent.log"

_configured = False

def get_logger(name: str) -> logging.Logger:
    global _configured
    if not _configured:
        _configured = True
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        fmt = logging.Formatter(
            fmt="%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Rotating file handler — 2 MB per file, keep 3 backups
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)

        root = logging.getLogger("sfw")
        root.setLevel(logging.DEBUG)
        root.addHandler(fh)
        root.addHandler(ch)

    return logging.getLogger(f"sfw.{name}")
