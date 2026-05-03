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

# In-memory peer state (safe_ip -> info dict)
_peer_ips  = {}
_peer_lock = threading.Lock()

# Callbacks fired instantly when a peer blocks/unblocks an IP
on_new_peer_block = None   # callable(ip: str, attack_type: str, node_id: str)
on_peer_unblock   = None   # callable(ip: str)

_blocklist_listener  = None
_peer_blocks_listener = None

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
            _start_realtime_listeners()
            log.info(f"Firebase connected (client_id={CLIENT_ID})")
            return _db
        except Exception as e:
            log.error(f"Firebase init failed: {e}")
            return None

# ── Real-time listeners ───────────────────────────────────────────────────────

def _handle_new_ip(ip: str, attack_type: str, node_id: str):
    """
    Called from any listener when a peer IP is discovered.
    Updates in-memory state and fires the GUI callback instantly.
    """
    safe_ip = ip.replace(".", "_")
    with _peer_lock:
        if safe_ip in _peer_ips:
            return   # already known, no need to fire again
        _peer_ips[safe_ip] = {
            "attack_type": attack_type,
            "blocked_at":  time.time(),
            "node_id": node_id
        }

    log.info(f"Real-time: new peer block detected → {ip} ({attack_type}) by {node_id}")

    cb = on_new_peer_block
    if cb:
        try:
            cb(ip, attack_type, node_id)
        except Exception as e:
            log.warning(f"on_new_peer_block callback error: {e}")


def _on_blocklist_change(event):
    """
    Listener on /blocklist.
    Fires whenever ANY client writes a new block entry or removes one.
    Rebuilt to handle all Firebase event shapes reliably.
    """
    try:
        data = event.data
        evt_path = event.path

        if data is None:
            # Deletion event — could be /cid/safe_ip or /cid or /
            parts = evt_path.strip("/").split("/")
            parts = [p for p in parts if p]

            if len(parts) == 2:
                # Single IP removed: /cid/safe_ip
                _cid, safe_ip = parts
                ip = safe_ip.replace("_", ".")
                with _peer_lock:
                    _peer_ips.pop(safe_ip, None)
                cb = on_peer_unblock
                if cb:
                    try: cb(ip)
                    except Exception as e: log.warning(f"on_peer_unblock error: {e}")

            elif len(parts) == 1:
                # Entire client subtree removed
                cid = parts[0]
                if cid != CLIENT_ID:
                    with _peer_lock:
                        to_remove = [k for k, v in _peer_ips.items()
                                     if v.get("node_id") == cid]
                    for safe_ip in to_remove:
                        ip = safe_ip.replace("_", ".")
                        with _peer_lock:
                            _peer_ips.pop(safe_ip, None)
                        cb = on_peer_unblock
                        if cb:
                            try: cb(ip)
                            except Exception as e: log.warning(f"on_peer_unblock error: {e}")

            elif len(parts) == 0:
                # Full blocklist cleared — unblock everything from peers
                with _peer_lock:
                    all_safe = list(_peer_ips.keys())
                    _peer_ips.clear()
                cb = on_peer_unblock
                if cb:
                    for safe_ip in all_safe:
                        ip = safe_ip.replace("_", ".")
                        try: cb(ip)
                        except Exception as e: log.warning(f"on_peer_unblock error: {e}")
            return

        if isinstance(data, dict):
            parts = path.strip("/").split("/")

            if parts == [""]:
                # Full /blocklist snapshot on initial connect
                for cid, ips in data.items():
                    if cid == CLIENT_ID:
                        continue
                    if not isinstance(ips, dict):
                        continue
                    for safe_ip, info in ips.items():
                        ip = safe_ip.replace("_", ".")
                        attack = info.get("attack_type", "peer_shared") if isinstance(info, dict) else "peer_shared"
                        _handle_new_ip(ip, attack, cid)

            elif len(parts) == 1:
                # A single client's full sub-tree: data = {safe_ip: info, ...}
                cid = parts[0]
                if cid == CLIENT_ID:
                    return
                for safe_ip, info in data.items():
                    ip = safe_ip.replace("_", ".")
                    attack = info.get("attack_type", "peer_shared") if isinstance(info, dict) else "peer_shared"
                    _handle_new_ip(ip, attack, cid)

            elif len(parts) == 2:
                # Single IP record written: /cid/safe_ip → info dict
                cid, safe_ip = parts
                if cid == CLIENT_ID:
                    return
                ip = safe_ip.replace("_", ".")
                attack = data.get("attack_type", "peer_shared") if isinstance(data, dict) else "peer_shared"
                _handle_new_ip(ip, attack, cid)

    except Exception as e:
        log.warning(f"_on_blocklist_change error: {e}")


def _on_peer_blocks_change(event):
    try:
        data = event.data
        path = event.path

        if data is None:
            return

        if isinstance(data, dict):
            parts = path.strip("/").split("/")

            if parts == [""]:
                for safe_ip, sources in data.items():
                    if not isinstance(sources, dict):
                        continue
                    for cid, info in sources.items():
                        if cid != CLIENT_ID:
                            ip = safe_ip.replace("_", ".")
                            attack = info.get("attack_type", "peer_shared") if isinstance(info, dict) else "peer_shared"
                            _handle_new_ip(ip, attack, cid)
                            break

            elif len(parts) == 1:
                safe_ip = parts[0]
                for cid, info in data.items():
                    if cid != CLIENT_ID:
                        ip = safe_ip.replace("_", ".")
                        attack = info.get("attack_type", "peer_shared") if isinstance(info, dict) else "peer_shared"
                        _handle_new_ip(ip, attack, cid)
                        break

    except Exception as e:
        log.warning(f"_on_peer_blocks_change error: {e}")


def _start_realtime_listeners():
    global _blocklist_listener, _peer_blocks_listener
    try:
        _blocklist_listener = _db.reference("/blocklist").listen(_on_blocklist_change)
        log.info("Real-time /blocklist listener attached")
    except Exception as e:
        log.warning(f"Could not attach /blocklist listener: {e} — starting poll fallback")
        _start_poll_fallback()

    try:
        _peer_blocks_listener = _db.reference("/peer_blocks").listen(_on_peer_blocks_change)
        log.info("Real-time /peer_blocks listener attached")
    except Exception as e:
        log.warning(f"Could not attach /peer_blocks listener: {e}")


def _start_poll_fallback():
    def _loop():
        while True:
            try:
                db = _get_db()
                if db:
                    snap = db.reference("/blocklist").get()
                    if snap and isinstance(snap, dict):
                        for cid, ips in snap.items():
                            if cid == CLIENT_ID or not isinstance(ips, dict):
                                continue
                            for safe_ip, info in ips.items():
                                ip = safe_ip.replace("_", ".")
                                attack = info.get("attack_type", "peer_shared") if isinstance(info, dict) else "peer_shared"
                                _handle_new_ip(ip, attack, cid)
            except Exception as e:
                log.warning(f"Poll fallback error: {e}")
            time.sleep(10)

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


def push_block(ip: str, attack_type: str, duration: int = 0) -> None:
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
        with _peer_lock:
            _peer_ips.pop(safe_ip, None)
        log.info(f"Removed block for {ip} from Firebase")
    except Exception as e:
        log.error(f"remove_block failed for {ip}: {e}")


def fetch_blocklist() -> list[dict]:
    with _peer_lock:
        return [
            {"ip": safe_ip.replace("_", "."), "attack_type": info["attack_type"]}
            for safe_ip, info in _peer_ips.items()
        ]


def fetch_all_firebase_ips() -> list[dict]:
    db = _get_db()
    if not db:
        return []

    results = {}

    try:
        blocklist_snap = db.reference("/blocklist").get()
        if blocklist_snap and isinstance(blocklist_snap, dict):
            for client_id, ips in blocklist_snap.items():
                if not isinstance(ips, dict):
                    continue
                for safe_ip, info in ips.items():
                    ip = safe_ip.replace("_", ".")
                    if ip not in results:
                        results[ip] = {
                            "ip": ip,
                            "attack_type": info.get("attack_type", "cloud_restore") if isinstance(info, dict) else "cloud_restore",
                            "node_id": client_id, # <-- FIX: Now passes the Node ID!
                        }
    except Exception as e:
        log.warning(f"fetch_all_firebase_ips: blocklist read failed: {e}")

    try:
        peer_snap = db.reference("/peer_blocks").get()
        if peer_snap and isinstance(peer_snap, dict):
            for safe_ip, sources in peer_snap.items():
                ip = safe_ip.replace("_", ".")
                if ip not in results and isinstance(sources, dict):
                    for cid, info in sources.items():
                        results[ip] = {
                            "ip": ip,
                            "attack_type": info.get("attack_type", "peer_shared") if isinstance(info, dict) else "peer_shared",
                            "node_id": cid, # <-- FIX: Now passes the Node ID!
                        }
                        break
    except Exception as e:
        log.warning(f"fetch_all_firebase_ips: peer_blocks read failed: {e}")

    log.info(f"fetch_all_firebase_ips: loaded {len(results)} IPs from Firebase")
    return list(results.values())
