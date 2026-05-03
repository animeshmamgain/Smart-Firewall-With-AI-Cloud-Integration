Directory structure:
└── sfw/
    ├── agent/
    │   ├── alert_store.py
    │   ├── cloud_hooks.py
    │   ├── config.py
    │   ├── database.py
    │   ├── detector_runner.py
    │   ├── dialogs.py
    │   ├── enforcer.py
    │   ├── event_consumer.py
    │   ├── gui.py
    │   ├── logger.py
    │   ├── main.py
    │   └── widgets.py
    └── ai/
        └── scripts/
            └── detector.py

================================================
FILE: agent/alert_store.py
================================================
[Binary file]


================================================
FILE: agent/cloud_hooks.py
================================================
[Binary file]


================================================
FILE: agent/config.py
================================================
from pathlib import Path
import socket
import fcntl
import struct
import os
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

AGENT_DIR   = Path(__file__).resolve().parent
PROJECT_DIR = AGENT_DIR.parent
SHARED_DIR  = PROJECT_DIR / "shared"
LOGS_DIR    = AGENT_DIR / "logs"

EVENTS_FILE = SHARED_DIR / "events.jsonl"
DB_FILE     = LOGS_DIR / "agent.db"

DEFAULT_MODE         = "auto"
AUTO_UNBLOCK_SECONDS = 999_999_999   # Permanent — blocks never expire automatically
MAX_RECENT_ALERTS    = 100
EVENT_POLL_INTERVAL  = 0.5
GUI_REFRESH_INTERVAL = 1000

INTERFACE = os.getenv("SFW_INTERFACE", "enp0s8")

def get_ip_address(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return "127.0.0.1"

local_ip = get_ip_address(INTERFACE)

WHITELIST = {
    "127.0.0.1",
    local_ip,
    "8.8.8.8",
}

THEME = {
    "bg":          "#0a0d14",
    "panel":       "#0f1520",
    "panel2":      "#131b2a",
    "border":      "#1e2d45",
    "accent":      "#00b8e6",
    "accent2":     "#7b2fff",
    "ok":          "#00d68f",
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



================================================
FILE: agent/database.py
================================================
import sqlite3
import json
import threading
import time
from pathlib import Path
from config import DB_FILE, LOGS_DIR
from logger import get_logger

log = get_logger("database")

class Database:
    def __init__(self, path: Path = DB_FILE):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._lock = threading.Lock()
        try:
            self._conn = sqlite3.connect(str(path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
            self._prune_old_records()
            log.info(f"Database ready at {path}")
        except Exception as e:
            log.error(f"Failed to open database at {path}: {e}")
            raise

    def _init_schema(self):
        with self._lock:
            try:
                c = self._conn.cursor()
                c.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        received_at REAL    NOT NULL,
                        src_ip      TEXT    NOT NULL,
                        attack_type TEXT    NOT NULL,
                        confidence  REAL,
                        source      TEXT,
                        recommended TEXT,
                        raw         TEXT    NOT NULL
                    )
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS actions (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        at          REAL    NOT NULL,
                        action      TEXT    NOT NULL,
                        ip          TEXT    NOT NULL,
                        reason      TEXT,
                        attack_type TEXT
                    )
                """)
                self._conn.commit()
            except Exception as e:
                log.error(f"Schema init failed: {e}")
                raise

    def _prune_old_records(self, days=7):
        cutoff = time.time() - (days * 86400)
        with self._lock:
            try:
                self._conn.execute("DELETE FROM alerts WHERE received_at < ?", (cutoff,))
                self._conn.execute("DELETE FROM actions WHERE at < ?", (cutoff,))
                self._conn.commit()
            except Exception as e:
                log.warning(f"Failed to prune old records: {e}")

    def log_alert(self, event: dict):
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO alerts (received_at, src_ip, attack_type, confidence, source, recommended, raw) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (time.time(), event.get("src_ip",""), event.get("attack_type","unknown"),
                     event.get("confidence",0.0), event.get("detection_source",""),
                     event.get("recommended_action",""), json.dumps(event)),
                )
                self._conn.commit()
            except Exception as e:
                log.error(f"Failed to log alert: {e}")

    def log_action(self, action: str, ip: str, reason: str = "", attack_type: str = ""):
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO actions (at, action, ip, reason, attack_type) VALUES (?, ?, ?, ?, ?)",
                    (time.time(), action, ip, reason, attack_type),
                )
                self._conn.commit()
            except Exception as e:
                log.error(f"Failed to log action '{action}' for {ip}: {e}")

    def recent_alerts(self, limit: int = 50):
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
            except Exception as e:
                log.error(f"Failed to fetch recent alerts: {e}")
                return []

    def recent_actions(self, limit: int = 50):
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
            except Exception as e:
                log.error(f"Failed to fetch recent actions: {e}")
                return []

    def get_active_blocks(self):
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT ip, MAX(at) as at, action, attack_type FROM actions "
                    "GROUP BY ip HAVING action='block'"
                ).fetchall()
                return [dict(r) for r in rows]
            except Exception as e:
                log.error(f"Failed to fetch active blocks: {e}")
                return []

    def stats(self) -> dict:
        with self._lock:
            try:
                n_alerts   = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                n_blocks   = self._conn.execute("SELECT COUNT(*) FROM actions WHERE action='block'").fetchone()[0]
                n_unblocks = self._conn.execute("SELECT COUNT(*) FROM actions WHERE action='unblock'").fetchone()[0]
                return {"alerts": n_alerts, "blocks": n_blocks, "unblocks": n_unblocks}
            except Exception as e:
                log.error(f"Failed to fetch stats: {e}")
                return {"alerts": 0, "blocks": 0, "unblocks": 0}

    def close(self):
        with self._lock:
            try:
                self._conn.close()
                log.info("Database connection closed")
            except Exception as e:
                log.warning(f"Error closing database: {e}")



================================================
FILE: agent/detector_runner.py
================================================
"""
detector_runner.py — Manages the AI detector as a subprocess.
"""

import subprocess
import threading
import signal
from collections import deque
from pathlib import Path

from config import PROJECT_DIR
from logger import get_logger

log = get_logger("detector_runner")


class DetectorRunner:
    DETECTOR_SCRIPT = PROJECT_DIR / "ai" / "scripts" / "detector.py"
    PYTHON_BIN      = PROJECT_DIR / "venv" / "bin" / "python3"
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



================================================
FILE: agent/dialogs.py
================================================
"""
dialogs.py — Themed modal dialogs.
"""

import customtkinter as ctk
from config import THEME
from widgets import tint


def _make_dialog(parent, title: str, width: int = 460, height: int = 200):
    """Common dialog scaffold."""
    dlg = ctk.CTkToplevel(parent)
    dlg.title(title)
    dlg.geometry(f"{width}x{height}")
    dlg.resizable(False, False)
    dlg.configure(fg_color=THEME["bg"])
    dlg.transient(parent)

    parent.update_idletasks()
    x = parent.winfo_x() + (parent.winfo_width() - width) // 2
    y = parent.winfo_y() + (parent.winfo_height() - height) // 2
    dlg.geometry(f"+{x}+{y}")

    # Defer grab_set until window is viewable
    dlg.after(100, lambda: dlg.grab_set() if dlg.winfo_exists() else None)
    return dlg

def confirm(parent, title: str, message: str, danger: bool = False) -> bool:
    result = {"value": False}
    dlg = _make_dialog(parent, title, 460, 200)
    border = THEME["danger"] if danger else THEME["accent"]
    title_color = border

    body = ctk.CTkFrame(dlg, fg_color=THEME["panel"],
                        border_color=border, border_width=1, corner_radius=6)
    body.pack(fill="both", expand=True, padx=14, pady=14)

    ctk.CTkLabel(body, text=title,
                 font=("Courier New", 13, "bold"),
                 text_color=title_color, anchor="w",
                 ).pack(fill="x", padx=16, pady=(14, 6))

    ctk.CTkLabel(body, text=message,
                 font=("Courier New", 11), text_color=THEME["text"],
                 anchor="w", justify="left", wraplength=400,
                 ).pack(fill="x", padx=16, pady=(0, 14))

    btn_row = ctk.CTkFrame(body, fg_color="transparent")
    btn_row.pack(side="bottom", fill="x", padx=14, pady=(0, 14))

    def on_yes(): result["value"] = True; dlg.destroy()
    def on_no():  dlg.destroy()

    confirm_color = THEME["danger"] if danger else THEME["accent"]
    ctk.CTkButton(btn_row, text="CANCEL", command=on_no,
                  fg_color="transparent", border_color=THEME["text_dim"], border_width=1,
                  hover_color=THEME["panel2"], text_color=THEME["text_dim"],
                  font=("Courier New", 11, "bold"), corner_radius=4, height=32, width=110,
                  ).pack(side="right", padx=4)
    ctk.CTkButton(btn_row, text="CONFIRM", command=on_yes,
                  fg_color="transparent", border_color=confirm_color, border_width=1,
                  hover_color=tint(confirm_color, 0.20),
                  text_color=confirm_color,
                  font=("Courier New", 11, "bold"), corner_radius=4, height=32, width=110,
                  ).pack(side="right", padx=4)

    dlg.bind("<Return>", lambda e: on_yes())
    dlg.bind("<Escape>", lambda e: on_no())
    parent.wait_window(dlg)
    return result["value"]


def info(parent, title: str, message: str) -> None:
    dlg = _make_dialog(parent, title, 460, 200)
    body = ctk.CTkFrame(dlg, fg_color=THEME["panel"],
                        border_color=THEME["accent"], border_width=1, corner_radius=6)
    body.pack(fill="both", expand=True, padx=14, pady=14)

    ctk.CTkLabel(body, text=title,
                 font=("Courier New", 13, "bold"),
                 text_color=THEME["accent"], anchor="w",
                 ).pack(fill="x", padx=16, pady=(14, 6))

    ctk.CTkLabel(body, text=message,
                 font=("Courier New", 11), text_color=THEME["text"],
                 anchor="w", justify="left", wraplength=400,
                 ).pack(fill="x", padx=16, pady=(0, 14))

    ctk.CTkButton(body, text="OK", command=dlg.destroy,
                  fg_color="transparent", border_color=THEME["accent"], border_width=1,
                  hover_color=tint(THEME["accent"], 0.20),
                  text_color=THEME["accent"],
                  font=("Courier New", 11, "bold"), corner_radius=4, height=32, width=110,
                  ).pack(side="right", padx=14, pady=(0, 14))

    dlg.bind("<Return>", lambda e: dlg.destroy())
    dlg.bind("<Escape>", lambda e: dlg.destroy())
    parent.wait_window(dlg)


def show_alert_detail(parent, record: dict) -> None:
    """Modal showing full alert details — used from right-click context."""
    dlg = _make_dialog(parent, "Alert Details", 600, 460)
    body = ctk.CTkFrame(dlg, fg_color=THEME["panel"],
                        border_color=THEME["accent"], border_width=1, corner_radius=6)
    body.pack(fill="both", expand=True, padx=14, pady=14)

    ev = record["event"]
    attack = ev.get("attack_type", "?")

    ctk.CTkLabel(body, text=f"  {attack.upper()}",
                 font=("Courier New", 16, "bold"),
                 text_color=THEME["danger"] if attack != "benign" else THEME["accent"],
                 anchor="w").pack(fill="x", padx=16, pady=(14, 4))

    ctk.CTkLabel(body, text=f"  Detected at {record['ts']}",
                 font=("Courier New", 10), text_color=THEME["text_dim"],
                 anchor="w").pack(fill="x", padx=16, pady=(0, 12))

    # Detail fields
    fields = [
        ("Source IP",      ev.get("src_ip", "?")),
        ("Destination",    ev.get("dst_ip", "?")),
        ("Confidence",     f"{ev.get('confidence', 0):.3f}"),
        ("Detection by",   ev.get("detection_source", "?")),
        ("Recommended",    ev.get("recommended_action", "?")),
        ("Status",         record["status"]),
    ]
    grid = ctk.CTkFrame(body, fg_color="transparent")
    grid.pack(fill="x", padx=16, pady=(0, 12))
    for i, (k, v) in enumerate(fields):
        ctk.CTkLabel(grid, text=f"  {k}:", font=("Courier New", 11),
                     text_color=THEME["text_dim"], anchor="w", width=140,
                     ).grid(row=i, column=0, sticky="w", pady=2)
        ctk.CTkLabel(grid, text=str(v), font=("Courier New", 11, "bold"),
                     text_color=THEME["text"], anchor="w",
                     ).grid(row=i, column=1, sticky="w", pady=2)

    # Evidence section
    evidence = ev.get("evidence", {})
    if evidence:
        ctk.CTkLabel(body, text="  EVIDENCE",
                     font=("Courier New", 10, "bold"),
                     text_color=THEME["accent"], anchor="w",
                     ).pack(fill="x", padx=16, pady=(8, 4))
        e_grid = ctk.CTkFrame(body, fg_color=THEME["panel2"], corner_radius=4)
        e_grid.pack(fill="x", padx=16, pady=(0, 12))
        for i, (k, v) in enumerate(evidence.items()):
            ctk.CTkLabel(e_grid, text=f"  {k}:", font=("Courier New", 10),
                         text_color=THEME["text_dim"], anchor="w", width=160,
                         ).grid(row=i, column=0, sticky="w", padx=8, pady=2)
            ctk.CTkLabel(e_grid, text=str(v), font=("Courier New", 10),
                         text_color=THEME["text"], anchor="w",
                         ).grid(row=i, column=1, sticky="w", padx=8, pady=2)

    ctk.CTkButton(body, text="CLOSE", command=dlg.destroy,
                  fg_color="transparent", border_color=THEME["accent"], border_width=1,
                  hover_color=tint(THEME["accent"], 0.20),
                  text_color=THEME["accent"],
                  font=("Courier New", 11, "bold"), corner_radius=4, height=32, width=110,
                  ).pack(side="bottom", padx=14, pady=(0, 14))

    dlg.bind("<Escape>", lambda e: dlg.destroy())
    dlg.bind("<Return>", lambda e: dlg.destroy())
    parent.wait_window(dlg)



================================================
FILE: agent/enforcer.py
================================================
[Binary file]


================================================
FILE: agent/event_consumer.py
================================================
"""
event_consumer.py — Tails the AI's events.jsonl in a background thread,
and checks heartbeat for true liveness.
"""

import json
import threading
import time
from pathlib import Path

from config import EVENTS_FILE, EVENT_POLL_INTERVAL, SHARED_DIR
from logger import get_logger

log = get_logger("event_consumer")

HEARTBEAT_FILE    = SHARED_DIR / "heartbeat.txt"
HEARTBEAT_TIMEOUT = 8.0   # seconds; older than this = stale


class EventConsumer:
    """Background tailer for the JSON-lines event stream."""

    def __init__(self, on_event, path: Path = EVENTS_FILE):
        self._on_event = on_event
        self._path     = path
        self._running  = False
        self._thread   = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()
        log.info(f"Event consumer started, tailing {self._path}")

    def stop(self):
        self._running = False
        log.info("Event consumer stopped")

    def liveness(self) -> str:
        if not HEARTBEAT_FILE.exists():
            return "down"
        try:
            ts  = float(HEARTBEAT_FILE.read_text().strip())
            age = time.time() - ts
            if age <= HEARTBEAT_TIMEOUT:
                return "live"
            if age <= 30:
                return "stale"
            return "down"
        except Exception as e:
            log.warning(f"Could not read heartbeat file: {e}")
            return "down"

    def heartbeat_age(self) -> float:
        if not HEARTBEAT_FILE.exists():
            return -1
        try:
            ts = float(HEARTBEAT_FILE.read_text().strip())
            return time.time() - ts
        except Exception as e:
            log.warning(f"Could not read heartbeat age: {e}")
            return -1

    def _tail_loop(self):
        position = 0
        try:
            if self._path.exists():
                position = self._path.stat().st_size
        except Exception as e:
            log.warning(f"Could not stat events file on startup: {e}")

        while self._running:
            try:
                if not self._path.exists():
                    time.sleep(EVENT_POLL_INTERVAL)
                    continue

                size = self._path.stat().st_size
                if size < position:
                    log.info("Events file was truncated — resetting read position")
                    position = 0

                if size > position:
                    with open(self._path, "r") as f:
                        f.seek(position)
                        for line in f:
                            line = line.strip()
                            if line:
                                self._dispatch(line)
                        position = f.tell()

            except Exception as e:
                log.error(f"Tail loop error: {e}")

            time.sleep(EVENT_POLL_INTERVAL)

    def _dispatch(self, line: str):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as e:
            log.warning(f"Skipping malformed event line: {e} — content: {line[:80]}")
            return
        try:
            self._on_event(event)
        except Exception as e:
            log.error(f"Event handler raised an exception: {e}")



================================================
FILE: agent/gui.py
================================================
import time
import tkinter as tk
import customtkinter as ctk
from tkinter import ttk

from config            import THEME, DEFAULT_MODE, GUI_REFRESH_INTERVAL
from enforcer          import Enforcer
from event_consumer    import EventConsumer
from database          import Database
from detector_runner   import DetectorRunner
from alert_store       import AlertStore
from widgets           import make_panel, make_section_header, make_button, make_entry, make_label, tint
from dialogs           import confirm, info, show_alert_detail
import cloud_hooks

class FirewallAgentUI:
    def __init__(self):
        self.mode   = DEFAULT_MODE
        self._dirty = True

        self.db        = Database()
        self.enforcer  = Enforcer(on_change=self._mark_dirty)
        self.consumer  = EventConsumer(on_event=self._handle_event)
        self.runner    = DetectorRunner()
        self.store     = AlertStore()

        ctk.set_appearance_mode("dark")
        self.root = ctk.CTk()
        self.root.title("Smart Firewall Agent")
        self.root.geometry("1280x820")
        self.root.minsize(1200, 760)
        self.root.configure(fg_color=THEME["bg"])

        self._build_ui()
        self._configure_treeview_style()

        # Register real-time peer-block callback BEFORE syncing
        # so any Firebase event that arrives during startup is handled
        cloud_hooks.on_new_peer_block = self._on_realtime_peer_block

        # SYNC STATE ON STARTUP
        self._sync_existing_blocks()

        self.consumer.start()
        self.runner.start()
        self.root.after(GUI_REFRESH_INTERVAL, self._refresh_loop)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _sync_existing_blocks(self):
        # Restore local DB blocks
        active_blocks = self.db.get_active_blocks()
        for record in active_blocks:
            self.enforcer.block(record["ip"], attack_type=record["attack_type"], auto=True)

        # Fetch ALL IPs from Firebase (blocklist + peer_blocks) and restore them
        try:
            firebase_ips = cloud_hooks.fetch_all_firebase_ips()
            for entry in firebase_ips:
                ip = entry["ip"]
                attack_type = entry.get("attack_type", "cloud_restore")
                if not self.enforcer.is_blocked(ip):
                    if self.enforcer.block(ip, attack_type=attack_type, auto=True):
                        self.db.log_action("block", ip, "cloud_restore", attack_type)
        except Exception as e:
            print(f"[gui] Firebase startup sync error: {e}")

        self._dirty = True

    def _build_ui(self):
        self._build_header()
        self._build_tabs()
        self._build_footer()

    def _build_header(self):
        hdr = ctk.CTkFrame(self.root, fg_color=THEME["panel"], border_color=THEME["accent"], border_width=1, corner_radius=0, height=60)
        hdr.pack(fill="x"); hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text="\u25c6 SMART FIREWALL AGENT", font=("Courier New", 20, "bold"), text_color=THEME["accent"]).pack(side="left", padx=22)

        self.ai_status_lbl = ctk.CTkLabel(hdr, text="\u25cf AI: starting...", font=("Courier New", 12, "bold"), text_color=THEME["text_dim"])
        self.ai_status_lbl.pack(side="right", padx=20)

        mode_box = ctk.CTkFrame(hdr, fg_color="transparent")
        mode_box.pack(side="right", padx=14)
        make_label(mode_box, "MODE:", color=THEME["text_dim"], font=("Courier New", 10, "bold")).pack(side="left", padx=(0, 10))
        self.mode_seg = ctk.CTkSegmentedButton(
            mode_box, values=["AUTO", "MANUAL"], command=self._mode_changed, font=("Courier New", 11, "bold"),
            selected_color=THEME["accent"], selected_hover_color=tint(THEME["accent"], 0.30),
            unselected_color=THEME["panel2"], unselected_hover_color=THEME["border"], text_color=THEME["text"], height=32,
        )
        self.mode_seg.set("AUTO" if self.mode == "auto" else "MANUAL")
        self.mode_seg.pack(side="left")

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(
            self.root, fg_color=THEME["panel"], segmented_button_fg_color=THEME["panel2"],
            segmented_button_selected_color=THEME["accent"], segmented_button_selected_hover_color=tint(THEME["accent"], 0.30),
            segmented_button_unselected_color=THEME["panel2"], segmented_button_unselected_hover_color=THEME["border"],
            text_color=THEME["text"], text_color_disabled=THEME["text_dim"], border_color=THEME["border"], border_width=1, corner_radius=6,
        )
        self.tabs.pack(fill="both", expand=True, padx=14, pady=10)

        for name in ("ALERTS", "BLOCKED", "DETECTOR"):
            self.tabs.add(name)

        self._build_alerts_tab(self.tabs.tab("ALERTS"))
        self._build_blocked_tab(self.tabs.tab("BLOCKED"))
        self._build_detector_tab(self.tabs.tab("DETECTOR"))

    def _build_alerts_tab(self, parent):
        cols = ("time", "src_ip", "attack", "conf", "src", "status")
        widths   = {"time": 110, "src_ip": 180, "attack": 200, "conf": 110, "src": 110, "status": 140}
        anchors  = {"time": "center", "src_ip": "w", "attack": "w", "conf": "center", "src": "center", "status": "center"}
        headings = {"time": "TIME", "src_ip": "SOURCE IP", "attack": "ATTACK", "conf": "CONFIDENCE", "src": "DETECT", "status": "STATUS"}
        self.alerts_tree = ttk.Treeview(parent, columns=cols, show="headings", height=16)
        for c in cols:
            self.alerts_tree.heading(c, text=headings[c], anchor=anchors[c])
            self.alerts_tree.column(c, width=widths[c], anchor=anchors[c])
        self.alerts_tree.pack(fill="both", expand=True, padx=14, pady=14)

        self.alerts_tree.bind("<Double-Button-1>", self._on_alert_double_click)
        self.alerts_tree.bind("<Button-3>", self._on_alert_right_click)

        make_label(parent, "  Tip: double-click for details   |   right-click for more actions", color=THEME["text_dim"], font=("Courier New", 11)).pack(fill="x", padx=18, pady=(0, 12))

    def _build_blocked_tab(self, parent):
        cols = ("ip", "attack", "type")
        widths   = {"ip": 280, "attack": 300, "type": 200}
        anchors  = {"ip": "w", "attack": "w", "type": "center"}
        headings = {"ip": "IP ADDRESS", "attack": "ATTACK", "type": "BLOCKED BY"}
        self.blocked_tree = ttk.Treeview(parent, columns=cols, show="headings", height=14)
        for c in cols:
            self.blocked_tree.heading(c, text=headings[c], anchor=anchors[c])
            self.blocked_tree.column(c, width=widths[c], anchor=anchors[c])
        self.blocked_tree.pack(fill="both", expand=True, padx=14, pady=14)

        self.blocked_tree.bind("<Button-3>", self._on_blocked_right_click)

        action_row = ctk.CTkFrame(parent, fg_color="transparent")
        action_row.pack(fill="x", padx=16, pady=(0, 14))
        make_button(action_row, "UNBLOCK SELECTED", self._unblock_selected, color=THEME["ok"]).pack(side="left", padx=4)
        make_button(action_row, "UNBLOCK ALL",      self._unblock_all,      color=THEME["warn"]).pack(side="right", padx=4)

    def _build_detector_tab(self, parent):
        info_row = ctk.CTkFrame(parent, fg_color="transparent")
        info_row.pack(fill="x", padx=16, pady=(14, 8))
        make_label(info_row, "  Live output from the AI detector subprocess:", color=THEME["text_dim"], font=("Courier New", 11)).pack(side="left")

        self.log_text = ctk.CTkTextbox(parent, font=("Courier New", 12), fg_color=THEME["panel2"], text_color=THEME["text"], scrollbar_button_color=THEME["border"], corner_radius=4)
        self.log_text.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.log_text.configure(state="disabled")

    def _build_footer(self):
        footer = ctk.CTkFrame(self.root, fg_color=THEME["panel"], border_color=THEME["border"], border_width=1, corner_radius=0, height=64)
        footer.pack(fill="x", side="bottom"); footer.pack_propagate(False)

        make_label(footer, "  Quick block:", color=THEME["text_dim"], font=("Courier New", 11)).pack(side="left", padx=(16, 6))

        self.ip_entry = make_entry(footer, "Enter IP, e.g. 192.168.1.50", width=240)
        self.ip_entry.pack(side="left", padx=4)
        self.ip_entry.bind("<Return>", lambda e: self._manual_block())

        make_button(footer, "\U0001F512 BLOCK",   self._manual_block,   color=THEME["danger"], width=110).pack(side="left", padx=4)
        make_button(footer, "\U0001F513 UNBLOCK", self._manual_unblock, color=THEME["ok"],     width=110).pack(side="left", padx=4)

        make_button(footer, "CLEAR HISTORY", self._clear_history, color=THEME["text_dim"], width=130).pack(side="right", padx=14)

    def _configure_treeview_style(self):
        style = ttk.Style(); style.theme_use("default")
        style.configure("Treeview", background=THEME["panel2"], foreground=THEME["text"], fieldbackground=THEME["panel2"], borderwidth=0, font=("Courier New", 12), rowheight=32)
        style.configure("Treeview.Heading", background=THEME["panel"], foreground=THEME["accent"], font=("Courier New", 12, "bold"), borderwidth=0, relief="flat", padding=(8, 6))
        style.map("Treeview", background=[("selected", THEME["accent"])], foreground=[("selected", THEME["bg"])])

    def _handle_event(self, event: dict):
        self.db.log_alert(event)
        cloud_hooks.push_alert(event)

        ip = event.get("src_ip", "")
        attack = event.get("attack_type", "unknown")

        if self.enforcer.is_blocked(ip):
            self.enforcer.block(ip, attack_type=attack, auto=True)
            self.store.add(event, "ALREADY_BLOCKED")
            self._dirty = True
            return

        if self.enforcer.block(ip, attack_type=attack, auto=True):
            self.db.log_action("block", ip, "auto", attack)
            cloud_hooks.push_block(ip, attack, 0)
            status = "BLOCKED"
        else:
            status = "EXISTING"

        self.store.add(event, status)
        self._dirty = True

    def _on_realtime_peer_block(self, ip: str, attack_type: str):
        """
        Called instantly from the Firebase background thread when a peer blocks an IP.
        Schedules the actual block+refresh on the Tkinter main thread (thread-safe).
        """
        self.root.after(0, self._apply_realtime_peer_block, ip, attack_type)

    def _apply_realtime_peer_block(self, ip: str, attack_type: str):
        """Runs on the main thread — safe to touch enforcer and UI."""
        if self.enforcer.is_blocked(ip):
            return
        if self.enforcer.block(ip, attack_type=attack_type, auto=True):
            self.db.log_action("block", ip, "peer_realtime", attack_type)
            self._dirty = True

    def _on_alert_double_click(self, _event):
        sel = self.alerts_tree.selection()
        if not sel: return
        tags = self.alerts_tree.item(sel[0])["tags"]
        if not tags: return
        record = self.store.find(tags[0])
        if record:
            show_alert_detail(self.root, record)

    def _on_alert_right_click(self, event):
        row = self.alerts_tree.identify_row(event.y)
        if not row: return
        self.alerts_tree.selection_set(row)
        tags = self.alerts_tree.item(row)["tags"]
        if not tags: return
        record = self.store.find(tags[0])
        if not record: return
        ip = record["event"].get("src_ip", "")

        menu = tk.Menu(self.root, tearoff=0, bg=THEME["panel"], fg=THEME["text"], activebackground=THEME["accent"], activeforeground=THEME["bg"], borderwidth=0)
        menu.add_command(label="View Details", command=lambda: show_alert_detail(self.root, record))
        menu.add_separator()
        menu.add_command(label=f"Block {ip}",   command=lambda: self._block_ip(ip, record["event"].get("attack_type", "manual")))
        menu.add_command(label=f"Unblock {ip}", command=lambda: self._unblock_ip(ip))
        menu.add_separator()
        menu.add_command(label="Copy IP", command=lambda: self._copy_to_clipboard(ip))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _on_blocked_right_click(self, event):
        row = self.blocked_tree.identify_row(event.y)
        if not row: return
        self.blocked_tree.selection_set(row)
        vals = self.blocked_tree.item(row)["values"]
        if not vals: return
        ip = vals[0]

        menu = tk.Menu(self.root, tearoff=0, bg=THEME["panel"], fg=THEME["text"], activebackground=THEME["accent"], activeforeground=THEME["bg"], borderwidth=0)
        menu.add_command(label=f"Unblock {ip}", command=lambda: self._unblock_ip(ip))
        menu.add_command(label="Copy IP",       command=lambda: self._copy_to_clipboard(ip))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _block_ip(self, ip: str, attack: str = "manual"):
        if self.enforcer.block(ip, attack_type=attack, auto=False):
            self.db.log_action("block", ip, "manual", attack)
            cloud_hooks.push_block(ip, attack, 0)

    def _unblock_ip(self, ip: str):
        if self.enforcer.unblock(ip):
            self.db.log_action("unblock", ip, "manual")
            cloud_hooks.remove_block(ip)

    def _copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _is_valid_ip(self, ip: str) -> bool:
        """Return True if ip is a valid IPv4 address."""
        parts = ip.strip().split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _manual_block(self):
        ip = self.ip_entry.get().strip()
        if not ip: return
        if not self._is_valid_ip(ip):
            info(self.root, "Invalid IP", f"'{ip}' is not a valid IPv4 address.\nExample: 192.168.1.50")
            return
        if self.enforcer.block(ip, attack_type="manual", auto=False):
            self.db.log_action("block", ip, "manual")
            cloud_hooks.push_block(ip, "manual", 0)
            self.ip_entry.delete(0, "end")
        else:
            info(self.root, "Block", f"Could not block {ip}.\nAlready blocked or whitelisted.")

    def _manual_unblock(self):
        ip = self.ip_entry.get().strip()
        if not ip: return
        if self.enforcer.unblock(ip):
            self.db.log_action("unblock", ip, "manual")
            cloud_hooks.remove_block(ip)
            self.ip_entry.delete(0, "end")
        else:
            info(self.root, "Unblock", f"{ip} is not currently blocked.")

    def _unblock_selected(self):
        sel = self.blocked_tree.selection()
        if not sel:
            info(self.root, "Unblock", "Select an IP from the list first."); return
        ip = self.blocked_tree.item(sel[0])["values"][0]
        if self.enforcer.unblock(ip):
            self.db.log_action("unblock", ip, "manual")
            cloud_hooks.remove_block(ip)

    def _unblock_all(self):
        n = len(self.enforcer.list_blocked())
        if n == 0: return
        if confirm(self.root, "Unblock All", f"Release ALL {n} blocked IP(s)?\nThis cannot be undone.", danger=True):
            for ip, _info in list(self.enforcer.list_blocked()):
                self.enforcer.unblock(ip)
                self.db.log_action("unblock", ip, "manual_all")
                cloud_hooks.remove_block(ip)
            self._dirty = True

    def _clear_history(self):
        if confirm(self.root, "Clear History", "Wipe ALL alert and action history?\nThis deletes the SQLite log permanently.\n(Active blocks are preserved.)", danger=True):
            self.db.close()
            from config import DB_FILE
            try: DB_FILE.unlink()
            except Exception: pass
            self.db = Database()
            self.store.clear_all()
            self._dirty = True

    def _mode_changed(self, value):
        self.mode = "auto" if value == "AUTO" else "manual"

    def _mark_dirty(self):
        self._dirty = True

    def _refresh_loop(self):
        if self._dirty:
            self._refresh_alerts()
            self._refresh_blocked_structure()
        
        self._refresh_log()
        self._refresh_ai_status()
        self._dirty = False
        self.root.after(GUI_REFRESH_INTERVAL, self._refresh_loop)

    def _refresh_alerts(self):
        sel_id = None
        sel = self.alerts_tree.selection()
        if sel:
            tags = self.alerts_tree.item(sel[0])["tags"]
            if tags: sel_id = tags[0]

        for row in self.alerts_tree.get_children():
            self.alerts_tree.delete(row)

        for r in self.store.list_recent():
            ev = r["event"]
            iid = self.alerts_tree.insert("", "end", values=(
                r["ts"], ev.get("src_ip", "?"), ev.get("attack_type", "?"),
                f"{ev.get('confidence', 0):.2f}", ev.get("detection_source", "?"), r["status"],
            ), tags=(r["id"],))
            if r["id"] == sel_id:
                self.alerts_tree.selection_set(iid)

    def _refresh_blocked_structure(self):
        sel_ip = None
        sel = self.blocked_tree.selection()
        if sel:
            vals = self.blocked_tree.item(sel[0])["values"]
            if vals: sel_ip = vals[0]

        for row in self.blocked_tree.get_children():
            self.blocked_tree.delete(row)

        for ip, info_ in self.enforcer.list_blocked():
            tag = "auto" if info_["auto"] else "manual"
            iid = self.blocked_tree.insert("", "end", values=(
                ip, info_["attack"], tag,
            ), tags=(ip,))
            if ip == sel_ip:
                self.blocked_tree.selection_set(iid)


    def _refresh_log(self):
        lines = self.runner.get_log_lines()
        if not lines: return
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("end", "\n".join(lines[-200:]))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _refresh_ai_status(self):
        liveness = self.consumer.liveness()
        if liveness == "live":
            self.ai_status_lbl.configure(text="\u25cf AI: live",  text_color=THEME["ok"])
        elif liveness == "stale":
            self.ai_status_lbl.configure(text="\u25cf AI: stale", text_color=THEME["warn"])
        else:
            self.ai_status_lbl.configure(text="\u25cf AI: down",  text_color=THEME["danger"])

    def _on_close(self):
        try: self.runner.stop()
        except Exception: pass
        try: self.consumer.stop()
        except Exception: pass
        try: self.enforcer.stop()
        except Exception: pass
        try: self.db.close()
        except Exception: pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()



================================================
FILE: agent/logger.py
================================================
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



================================================
FILE: agent/main.py
================================================
"""
main.py — Firewall agent entry point.

Run with sudo (iptables requires root):
  sudo python3 ~/sfw/agent/main.py
"""

import os
import sys

from gui import FirewallAgentUI


def main():
    if os.geteuid() != 0:
        print("ERROR: Firewall agent requires root for iptables.")
        print("Run with: sudo python3 ~/sfw/agent/main.py")
        sys.exit(1)

    app = FirewallAgentUI()
    app.run()


if __name__ == "__main__":
    main()



================================================
FILE: agent/widgets.py
================================================
[Binary file]


================================================
FILE: ai/scripts/detector.py
================================================
import sys
import time
import json
import signal
import socket
import fcntl
import struct
from pathlib import Path
import os
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
from collections import defaultdict, deque

import numpy as np
import joblib
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP

def get_ip_address(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return "127.0.0.1"

INTERFACE = os.getenv("SFW_INTERFACE", "enp0s8")
VICTIM_IP       = get_ip_address(INTERFACE)
WINDOW_SEC      = 10
SCORE_INTERVAL  = 2.0
ALERT_COOLDOWN  = 5.0

MIN_PACKETS_FOR_RULES      = 10
MIN_PACKETS_FOR_PREDICTION = 30
PORT_SCAN_RULE_THRESHOLD   = 30

EXCLUDE_SRC_IPS = {VICTIM_IP, "127.0.0.1"}

CLASS_THRESHOLDS = {
    "port_scan":       0.65,
    "brute_force_ssh": 0.65,
    "brute_force_ftp": 0.65,
    "dos_flood":       0.65,
    "dos_slow":        0.45,
    "benign":          1.01,
}

ACTION_MAP = {
    "port_scan":       "block",
    "brute_force_ssh": "block",
    "brute_force_ftp": "block",
    "dos_flood":       "rate_limit",
    "dos_slow":        "rate_limit",
}

BASE_DIR    = Path(__file__).resolve().parent.parent.parent
AI_DIR      = BASE_DIR / "ai"
SHARED_DIR  = BASE_DIR / "shared"
MODEL_PATH  = AI_DIR / "models" / "sfw_model.joblib"
EVENTS_PATH = SHARED_DIR / "events.jsonl"
HEARTBEAT_PATH = SHARED_DIR / "heartbeat.txt"

packet_buffer = defaultdict(deque)
last_alert    = {}
running       = True

def packet_handler(pkt):
    if IP not in pkt:
        return
    src_ip = pkt[IP].src
    if src_ip in EXCLUDE_SRC_IPS:
        return
    
    info = {
        "ts":    float(pkt.time),
        "size":  len(pkt),
        "dst":   pkt[IP].dst,
        "dport": None,
        "flags": None,
        "proto": "OTHER",
    }
    if TCP in pkt:
        info["dport"] = pkt[TCP].dport
        info["flags"] = int(pkt[TCP].flags)
        info["proto"] = "TCP"
    elif UDP in pkt:
        info["dport"] = pkt[UDP].dport
        info["proto"] = "UDP"
    elif ICMP in pkt:
        info["proto"] = "ICMP"
    
    packet_buffer[src_ip].append(info)

def evict_old(buf, now, window_sec):
    cutoff = now - window_sec
    while buf and buf[0]["ts"] < cutoff:
        buf.popleft()

def compute_features(pkts):
    if len(pkts) < 2:
        return None
    
    timestamps = [p["ts"] for p in pkts]
    sizes      = [p["size"] for p in pkts]
    dst_ports  = [p["dport"] for p in pkts if p["dport"] is not None]
    dst_ips    = [p["dst"] for p in pkts]
    flows      = [(p["dst"], p["dport"]) for p in pkts if p["dport"] is not None]
    
    syn_count = sum(1 for p in pkts if p["flags"] is not None and p["flags"] & 0x02 and not (p["flags"] & 0x10))
    rst_count = sum(1 for p in pkts if p["flags"] is not None and p["flags"] & 0x04)
    tcp_count = sum(1 for p in pkts if p["proto"] == "TCP")
    udp_count = sum(1 for p in pkts if p["proto"] == "UDP")
    
    iats = np.diff(sorted(timestamps)) if len(timestamps) > 1 else [0.0]
    
    return {
        "pkt_count":        len(pkts),
        "byte_count":       sum(sizes),
        "unique_dst_ports": len(set(dst_ports)),
        "unique_dst_ips":   len(set(dst_ips)),
        "syn_count":        syn_count,
        "syn_ratio":        syn_count / len(pkts),
        "rst_count":        rst_count,
        "mean_pkt_size":    float(np.mean(sizes)),
        "std_pkt_size":     float(np.std(sizes)),
        "mean_iat":         float(np.mean(iats)),
        "flow_count":       len(set(flows)),
        "tcp_udp_ratio":    tcp_count / max(tcp_count + udp_count, 1),
    }

def rule_based_detect(features):
    pkts  = features["pkt_count"]
    ports = features["unique_dst_ports"]
    syn   = features["syn_count"]
    syn_r = features["syn_ratio"]
    flows = features["flow_count"]
    iat   = features["mean_iat"]
    
    if ports >= PORT_SCAN_RULE_THRESHOLD:
        return ("port_scan", 1.0, "rule_high_port_count")
    if pkts >= 5000:
        return ("dos_flood", 1.0, "rule_volumetric")
    if syn >= 1000 and syn_r >= 0.6:
        return ("dos_flood", 1.0, "rule_syn_flood")
    if flows >= 100 and pkts < 2000 and iat > 0.01:
        return ("dos_slow", 0.95, "rule_slow_dos")
    return None

def emit_alert(src_ip, predicted_class, confidence, features, source):
    if predicted_class == "benign":
        return None
    
    threshold = CLASS_THRESHOLDS.get(predicted_class, 0.65)
    if confidence < threshold:
        return None
    
    now = time.time()
    key = (src_ip, predicted_class)
    if key in last_alert and (now - last_alert[key]) < ALERT_COOLDOWN:
        return None
    last_alert[key] = now
    
    event = {
        "timestamp":          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "src_ip":             src_ip,
        "dst_ip":             VICTIM_IP,
        "attack_type":        predicted_class,
        "confidence":         round(float(confidence), 3),
        "detection_source":   source,
        "evidence": {
            "pkt_count":        features["pkt_count"],
            "unique_dst_ports": features["unique_dst_ports"],
            "syn_ratio":        round(features["syn_ratio"], 3),
            "flow_count":       features["flow_count"],
            "window_sec":       WINDOW_SEC,
        },
        "recommended_action": ACTION_MAP.get(predicted_class, "alert"),
    }
    
    if EVENTS_PATH.exists() and EVENTS_PATH.stat().st_size > 5 * 1024 * 1024:
        EVENTS_PATH.write_text("")
        
    with open(EVENTS_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    
    return event

def score_loop(model, feature_cols):
    print(f"[{time.strftime('%H:%M:%S')}] Detector running on {INTERFACE}.")
    print(f"[{time.strftime('%H:%M:%S')}] Min pkts: rules={MIN_PACKETS_FOR_RULES}, ML={MIN_PACKETS_FOR_PREDICTION}")
    print(f"[{time.strftime('%H:%M:%S')}] Events -> {EVENTS_PATH}\n")
    
    while running:
        time.sleep(SCORE_INTERVAL)
        now = time.time()
        ts  = time.strftime("%H:%M:%S")

        try:
            HEARTBEAT_PATH.write_text(str(now))
        except Exception:
            pass
        
        for src_ip in list(packet_buffer.keys()):
            buf = packet_buffer[src_ip]
            evict_old(buf, now, WINDOW_SEC)
            
            if len(buf) < MIN_PACKETS_FOR_RULES:
                continue
            
            features = compute_features(list(buf))
            if features is None:
                continue
            
            rule_result = rule_based_detect(features)
            if rule_result is not None:
                label, conf, rule_name = rule_result
                print(f"[{ts}] RULE  src={src_ip:15s} pred={label:18s} conf={conf:.2f} via={rule_name} pkts={features['pkt_count']} ports={features['unique_dst_ports']}")
                event = emit_alert(src_ip, label, conf, features, source="rule")
                if event:
                    print(f"           -> emitted: {label} ({event['recommended_action']})")
                continue
            
            if len(buf) < MIN_PACKETS_FOR_PREDICTION:
                continue
            
            X = np.array([[features[c] for c in feature_cols]])
            probs = model.predict_proba(X)[0]
            idx   = int(np.argmax(probs))
            pred  = model.classes_[idx]
            conf  = float(probs[idx])
            
            threshold = CLASS_THRESHOLDS.get(pred, 0.65)
            is_alert  = (pred != "benign") and (conf >= threshold)
            tag = "ALERT" if is_alert else "     "
            
            print(f"[{ts}] {tag} src={src_ip:15s} pred={pred:18s} conf={conf:.3f} (thr={threshold:.2f}) pkts={features['pkt_count']}")
            
            if is_alert:
                event = emit_alert(src_ip, pred, conf, features, source="ml")
                if event:
                    print(f"           -> emitted: {pred} ({event['recommended_action']})")

def signal_handler(signum, frame):
    global running
    print(f"\n[{time.strftime('%H:%M:%S')}] Shutting down...")
    running = False

def main():
    EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVENTS_PATH.touch()
    
    print(f"[{time.strftime('%H:%M:%S')}] Loading model from {MODEL_PATH}")
    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    feature_cols = artifact["feature_cols"]
    print(f"[{time.strftime('%H:%M:%S')}] Model loaded. Classes: {list(model.classes_)}")
    
    signal.signal(signal.SIGINT, signal_handler)
    
    sniffer = AsyncSniffer(iface=INTERFACE, filter="ip", prn=packet_handler, store=False)
    sniffer.start()
    print(f"[{time.strftime('%H:%M:%S')}] Sniffer started on {INTERFACE}")
    
    try:
        score_loop(model, feature_cols)
    finally:
        sniffer.stop()
        print(f"[{time.strftime('%H:%M:%S')}] Detector stopped cleanly.")

if __name__ == "__main__":
    main()


