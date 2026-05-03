import os
import time
import threading
import socket
from pathlib import Path
from dotenv import load_dotenv
from logger import get_logger

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

log = get_logger("cloud_hooks")

FIREBASE_CREDENTIALS_PATH = os.getenv(
    "FIREBASE_CREDS",
    str(Path(__file__).resolve().parent / "serviceAccountKey.json"),
)
FIREBASE_DATABASE_URL = os.getenv("FIREBASE_DB_URL", "")
CLIENT_ID = os.getenv("SFW_CLIENT_ID", socket.gethostname())

_db        = None
_init_lock = threading.Lock()
_peer_ips  = {}          # ip -> {"attack_type": str, "blocked_at": float}
_peer_lock = threading.Lock()
_listener  = None        # Firebase streaming listener handle

# ── Init ──────────────────────────────────────────────────────────────────────

def _get_db():
    global _db
    if _db is not None:
        return _db
    with _init_lock:
        if _db is not None:
            return _db
        if not FIREBASE_DATABASE_URL:
            log.info("FIREBASE_DB_URL not set — cloud sync disabled")
            return None
        try:
            import firebase_admin
            from firebase_admin import credentials, db as firebase_db
        except ImportError:
            log.warning("firebase-admin not installed — cloud sync disabled")
            return None
        try:
            if not firebase_admin._apps:
                cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
                firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_DATABASE_URL})
            _db = firebase_db
            _start_realtime_listener()
            log.info(f"Firebase connected (client_id={CLIENT_ID})")
            return _db
        except Exception as e:
            log.error(f"Firebase init failed: {e}")
            return None

# ── Real-time listener (instant updates) ─────────────────────────────────────

def _on_peer_blocks_change(event):
    """
    Called instantly by Firebase whenever /peer_blocks changes.
    event.data is the full snapshot of /peer_blocks or a sub-path update.
    """
    try:
        data = event.data
        new_peers = {}

        if data is None:
            # All peer blocks cleared
            with _peer_lock:
                _peer_ips.clear()
            log.info("Peer blocks cleared (real-time)")
            return

        if isinstance(data, dict):
            for safe_ip, sources in data.items():
                if not isinstance(sources, dict):
                    continue
                # Only add if another peer (not us) has this blocked
                for cid, info in sources.items():
                    if cid != CLIENT_ID:
                        new_peers[safe_ip] = {
                            "attack_type": info.get("attack_type", "peer_shared"),
                            "blocked_at":  info.get("blocked_at", time.time()),
                        }
                        break

        with _peer_lock:
            _peer_ips.clear()
            _peer_ips.update(new_peers)

        if new_peers:
            log.info(f"Real-time peer update: {len(new_peers)} IPs from peers")

    except Exception as e:
        log.warning(f"Real-time listener error: {e}")


def _start_realtime_listener():
    """Attach a Firebase streaming listener to /peer_blocks."""
    global _listener
    try:
        ref = _db.reference("/peer_blocks")
        _listener = ref.listen(_on_peer_blocks_change)
        log.info("Real-time peer_blocks listener attached")
    except Exception as e:
        log.warning(f"Could not attach real-time listener: {e} — falling back to polling")
        _start_poll_fallback()


def _start_poll_fallback():
    """Fallback polling every 5s if streaming listener fails."""
    def _loop():
        while True:
            try:
                db = _get_db()
                if db:
                    snap = db.reference("/peer_blocks").get()
                    new_peers = {}
                    if snap:
                        for safe_ip, sources in snap.items():
                            if isinstance(sources, dict):
                                for cid, info in sources.items():
                                    if cid != CLIENT_ID:
                                        new_peers[safe_ip] = {
                                            "attack_type": info.get("attack_type", "peer_shared"),
                                            "blocked_at":  info.get("blocked_at", time.time()),
                                        }
                                        break
                    with _peer_lock:
                        _peer_ips.clear()
                        _peer_ips.update(new_peers)
            except Exception as e:
                log.warning(f"Peer poll error: {e}")
            time.sleep(5)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

# ── Public API ────────────────────────────────────────────────────────────────

def push_alert(event: dict) -> None:
    db = _get_db()
    if not db:
        return
    try:
        payload = {
            "client_id":   CLIENT_ID,
            "src_ip":      event.get("src_ip", ""),
            "attack_type": event.get("attack_type", "unknown"),
            "confidence":  event.get("confidence", 0.0),
            "recommended": event.get("recommended_action", ""),
            "timestamp":   time.time(),
            "ts_human":    time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        db.reference(f"/threats/{CLIENT_ID}").push(payload)
    except Exception as e:
        log.error(f"push_alert failed: {e}")


def push_block(ip: str, attack_type: str, duration: int) -> None:
    db = _get_db()
    if not db:
        return
    try:
        record = {
            "client_id":   CLIENT_ID,
            "attack_type": attack_type,
            "blocked_at":  time.time(),
            "ts_human":    time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_s":  duration,
        }
        safe_ip = ip.replace(".", "_")
        db.reference(f"/blocklist/{CLIENT_ID}/{safe_ip}").set(record)
        db.reference(f"/peer_blocks/{safe_ip}/{CLIENT_ID}").set({
            "blocked_at":  record["blocked_at"],
            "attack_type": attack_type,
        })
        log.info(f"Pushed block for {ip} ({attack_type}) to Firebase")
    except Exception as e:
        log.error(f"push_block failed for {ip}: {e}")


def remove_block(ip: str) -> None:
    db = _get_db()
    if not db:
        return
    try:
        safe_ip = ip.replace(".", "_")
        db.reference(f"/blocklist/{CLIENT_ID}/{safe_ip}").delete()
        db.reference(f"/peer_blocks/{safe_ip}/{CLIENT_ID}").delete()
        log.info(f"Removed block for {ip} from Firebase")
    except Exception as e:
        log.error(f"remove_block failed for {ip}: {e}")


def fetch_blocklist() -> list[dict]:
    """
    Returns list of dicts: [{"ip": "1.2.3.4", "attack_type": "port_scan"}, ...]
    Called by gui._apply_peer_blocks every second.
    """
    with _peer_lock:
        return [
            {"ip": safe_ip.replace("_", "."), "attack_type": info["attack_type"]}
            for safe_ip, info in _peer_ips.items()
        ]
