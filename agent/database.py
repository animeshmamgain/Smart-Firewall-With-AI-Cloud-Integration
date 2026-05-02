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
