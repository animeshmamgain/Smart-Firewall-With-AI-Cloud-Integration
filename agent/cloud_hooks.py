import os
import time
import threading
import socket

FIREBASE_CREDENTIALS_PATH = os.environ.get(
    "FIREBASE_CREDS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "serviceAccountKey.json"),
)

FIREBASE_DATABASE_URL = os.environ.get(
    "FIREBASE_DB_URL",
    "https://smart-firewall-ai-default-rtdb.asia-southeast1.firebasedatabase.app",
)

CLIENT_ID = os.environ.get(
    "nottyguru",
    socket.gethostname(),
)

PEER_SYNC_INTERVAL = 10

_db   = None
_init_lock = threading.Lock()
_peer_ips  = set()
_peer_lock = threading.Lock()
_listener_thread = None

def _get_db():
    global _db
    if _db is not None:
        return _db
    with _init_lock:
        if _db is not None:
            return _db
        try:
            import firebase_admin
            from firebase_admin import credentials, db as firebase_db
        except ImportError:
            return None
        try:
            if not firebase_admin._apps:
                cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
                firebase_admin.initialize_app(cred, {
                    "databaseURL": FIREBASE_DATABASE_URL,
                })
            _db = firebase_db
            _start_peer_listener()
            return _db
        except Exception:
            return None

def _start_peer_listener():
    global _listener_thread
    if _listener_thread and _listener_thread.is_alive():
        return
    _listener_thread = threading.Thread(target=_peer_sync_loop, daemon=True)
    _listener_thread.start()

def _peer_sync_loop():
    while True:
        try:
            db = _get_db()
            if db:
                snap = db.reference("/peer_blocks").get()
                if snap:
                    new_peers = set()
                    for safe_ip, sources in snap.items():
                        if isinstance(sources, dict):
                            if any(cid != CLIENT_ID for cid in sources):
                                new_peers.add(safe_ip)
                    with _peer_lock:
                        _peer_ips.clear()
                        _peer_ips.update(new_peers)
        except Exception:
            pass
        time.sleep(PEER_SYNC_INTERVAL)

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
    except Exception:
        pass

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
    except Exception:
        pass

def remove_block(ip: str) -> None:
    db = _get_db()
    if not db:
        return
    try:
        safe_ip = ip.replace(".", "_")
        db.reference(f"/blocklist/{CLIENT_ID}/{safe_ip}").delete()
        db.reference(f"/peer_blocks/{safe_ip}/{CLIENT_ID}").delete()
    except Exception:
        pass

def fetch_blocklist() -> list:
    with _peer_lock:
        return [ip.replace("_", ".") for ip in _peer_ips]
