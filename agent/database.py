import sqlite3
import json
import threading
import time
from pathlib import Path
from config import DB_FILE, LOGS_DIR

class Database:
    def __init__(self, path: Path = DB_FILE):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        self._prune_old_records()

    def _init_schema(self):
        with self._lock:
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
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    at         REAL NOT NULL,
                    action     TEXT NOT NULL,
                    ip         TEXT NOT NULL,
                    reason     TEXT,
                    attack_type TEXT
                )
            """)
            self._conn.commit()

    def _prune_old_records(self, days=7):
        cutoff = time.time() - (days * 86400)
        with self._lock:
            self._conn.execute("DELETE FROM alerts WHERE received_at < ?", (cutoff,))
            self._conn.execute("DELETE FROM actions WHERE at < ?", (cutoff,))
            self._conn.commit()

    def log_alert(self, event: dict):
        with self._lock:
            self._conn.execute(
                "INSERT INTO alerts (received_at, src_ip, attack_type, confidence, source, recommended, raw) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), event.get("src_ip", ""), event.get("attack_type", "unknown"), event.get("confidence", 0.0), event.get("detection_source", ""), event.get("recommended_action", ""), json.dumps(event)),
            )
            self._conn.commit()

    def log_action(self, action: str, ip: str, reason: str = "", attack_type: str = ""):
        with self._lock:
            self._conn.execute(
                "INSERT INTO actions (at, action, ip, reason, attack_type) VALUES (?, ?, ?, ?, ?)",
                (time.time(), action, ip, reason, attack_type),
            )
            self._conn.commit()

    def recent_alerts(self, limit: int = 50):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def recent_actions(self, limit: int = 50):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def stats(self) -> dict:
        with self._lock:
            n_alerts  = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            n_blocks  = self._conn.execute("SELECT COUNT(*) FROM actions WHERE action='block'").fetchone()[0]
            n_unblocks= self._conn.execute("SELECT COUNT(*) FROM actions WHERE action='unblock'").fetchone()[0]
            return {"alerts": n_alerts, "blocks": n_blocks, "unblocks": n_unblocks}

    def close(self):
        with self._lock:
            self._conn.close()
