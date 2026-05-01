"""
cloud_hooks.py — Firebase Realtime Database integration for live threat sharing.

Architecture:
  Every client (firewall node) has a unique CLIENT_ID.
  Firebase paths:
    /threats/{client_id}/{push_key}   — alerts this client has seen
    /blocklist/{client_id}/{ip}       — IPs this client has blocked
    /peer_blocks/{ip}/{client_id}     — cross-client union index

  fetch_blocklist() returns peer-shared IPs (from all OTHER clients).

Setup:
  1. pip install firebase-admin
  2. Download your Firebase service account JSON from Firebase Console
     → Project Settings → Service Accounts → Generate new private key
  3. Set FIREBASE_CREDENTIALS_PATH below (or set env var FIREBASE_CREDS)
  4. Set FIREBASE_DATABASE_URL below (or set env var FIREBASE_DB_URL)
  5. Set CLIENT_ID below to something unique per machine (hostname, MAC, etc.)

  Or use the environment variables so each client can be configured
  independently without editing this file:
    export FIREBASE_CREDS=/path/to/serviceAccountKey.json
    export FIREBASE_DB_URL=https://your-project-default-rtdb.firebaseio.com
    export SFW_CLIENT_ID=client_a
"""

import os
import time
import threading
import socket

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
# Edit these OR set the environment variables shown above.

FIREBASE_CREDENTIALS_PATH = os.environ.get(
    "FIREBASE_CREDS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "serviceAccountKey.json"),
)

FIREBASE_DATABASE_URL = os.environ.get(
    "FIREBASE_DB_URL",
    "https://smart-firewall-ai-default-rtdb.asia-southeast1.firebasedatabase.app",  # <-- change this
)

# Unique name for this firewall node. Defaults to hostname.
CLIENT_ID = os.environ.get(
    "nottyguru",
    socket.gethostname(),
)

# How often (seconds) the background listener syncs peer blocks
PEER_SYNC_INTERVAL = 10

# ─── INTERNAL STATE ───────────────────────────────────────────────────────────
_db   = None          # firebase_admin db reference
_init_lock = threading.Lock()
_peer_ips  = set()    # IPs shared by ANY other client
_peer_lock = threading.Lock()
_listener_thread = None


# ─── INIT ─────────────────────────────────────────────────────────────────────

def _get_db():
    """Lazy-init Firebase. Returns the db module or None on failure."""
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
            print("[cloud_hooks] firebase-admin not installed — threat sharing disabled.")
            print("[cloud_hooks] Run: pip install firebase-admin")
            return None

        try:
            if not firebase_admin._apps:
                cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
                firebase_admin.initialize_app(cred, {
                    "databaseURL": FIREBASE_DATABASE_URL,
                })

            _db = firebase_db
            print(f"[cloud_hooks] Firebase connected. Client ID: {CLIENT_ID}")
            _start_peer_listener()
            return _db

        except Exception as e:
            print(f"[cloud_hooks] Firebase init failed: {e}")
            print("[cloud_hooks] Threat sharing disabled — running standalone.")
            return None


def _start_peer_listener():
    """Start background thread that polls peer blocks from Firebase."""
    global _listener_thread
    if _listener_thread and _listener_thread.is_alive():
        return
    _listener_thread = threading.Thread(target=_peer_sync_loop, daemon=True)
    _listener_thread.start()


def _peer_sync_loop():
    """Periodically fetch the union of all peer-shared IPs from Firebase."""
    while True:
        try:
            db = _get_db()
            if db:
                # /peer_blocks is a flat dict:  { "1_2_3_4": {client_id: {...}, ...} }
                snap = db.reference("/peer_blocks").get()
                if snap:
                    new_peers = set()
                    for safe_ip, sources in snap.items():
                        # Only count it if at least one OTHER client posted it
                        if isinstance(sources, dict):
                            if any(cid != CLIENT_ID for cid in sources):
                                new_peers.add(safe_ip)
                    with _peer_lock:
                        _peer_ips.clear()
                        _peer_ips.update(new_peers)
                    if new_peers:
                        print(f"[cloud_hooks] Peer sync: {len(new_peers)} peer-blocked IPs")
        except Exception as e:
            print(f"[cloud_hooks] Peer sync error: {e}")

        time.sleep(PEER_SYNC_INTERVAL)


# ─── PUBLIC API (called by gui.py) ────────────────────────────────────────────

def push_alert(event: dict) -> None:
    """
    Send an alert to Firebase under /threats/{client_id}.
    Called every time the AI detects a new threat on this node.
    """
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
        print(f"[cloud_hooks] push_alert error: {e}")


def push_block(ip: str, attack_type: str, duration: int) -> None:
    """
    Share a block decision with all peer clients.
    Writes to:
      /blocklist/{client_id}/{ip}   — this client's own block log
      /peer_blocks/{ip}/{client_id} — the cross-client union index
    """
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

        # Sanitise IP for use as a Firebase key (dots → underscores)
        safe_ip = ip.replace(".", "_")

        # Own log
        db.reference(f"/blocklist/{CLIENT_ID}/{safe_ip}").set(record)

        # Peer-visible index — keyed by client_id so multiple clients can
        # independently flag the same IP without overwriting each other
        db.reference(f"/peer_blocks/{safe_ip}/{CLIENT_ID}").set({
            "blocked_at":  record["blocked_at"],
            "attack_type": attack_type,
        })

        print(f"[cloud_hooks] Pushed block: {ip} ({attack_type}) to Firebase")

    except Exception as e:
        print(f"[cloud_hooks] push_block error: {e}")


def fetch_blocklist() -> list:
    """
    Return IPs that OTHER clients have blocked.
    Called by the GUI refresh loop to apply peer-shared blocks locally.

    Returns a list of plain IP strings, e.g. ["1.2.3.4", "5.6.7.8"].
    """
    with _peer_lock:
        # Convert safe_ip keys back to real IPs before returning
        return [ip.replace("_", ".") for ip in _peer_ips]
