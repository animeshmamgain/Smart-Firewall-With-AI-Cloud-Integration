"""
config.py — Constants for the firewall agent.
"""

from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────
AGENT_DIR   = Path(__file__).resolve().parent
PROJECT_DIR = AGENT_DIR.parent
SHARED_DIR  = PROJECT_DIR / "shared"
LOGS_DIR    = AGENT_DIR / "logs"

EVENTS_FILE = SHARED_DIR / "events.jsonl"
DB_FILE     = LOGS_DIR / "agent.db"

# ── Behavior ─────────────────────────────────────────────────────
DEFAULT_MODE         = "auto"
AUTO_UNBLOCK_SECONDS = 300
MAX_RECENT_ALERTS    = 100
EVENT_POLL_INTERVAL  = 0.5
GUI_REFRESH_INTERVAL = 1000

WHITELIST = {
    "127.0.0.1",
    "192.168.254.10",
    "8.8.8.8",
}

# ── UI Theme (cyber-pro: dark navy + cyan/purple accents, muted) ─
THEME = {
    "bg":          "#0a0d14",
    "panel":       "#0f1520",
    "panel2":      "#131b2a",
    "border":      "#1e2d45",
    "accent":      "#00b8e6",   # softened cyan
    "accent2":     "#7b2fff",
    "ok":          "#00d68f",   # softened green
    "warn":        "#ffaa00",
    "danger":      "#ff3366",
    "text":        "#c8daf0",
    "text_dim":    "#4a6080",
    "font_mono":   ("Courier New", 11),
    "font_small":  ("Courier New", 9),
    "font_header": ("Courier New", 13, "bold"),
}

ACTION_MAP = {
    "block":      "block",
    "rate_limit": "block",
}
