"""
enforcer.py — iptables block/unblock with auto-unblock timer.

The enforcer is the only component that touches iptables.
It maintains an in-memory map of {ip: (blocked_at, attack_type)}
and runs a background thread to release expired blocks.
"""

import subprocess
import threading
import time
from collections import OrderedDict

from config import AUTO_UNBLOCK_SECONDS, WHITELIST


class Enforcer:
    """Pure iptables logic — no UI, no event parsing."""

    def __init__(self, on_change=None):
        # OrderedDict preserves insertion order so UI shows oldest blocks first
        self._blocked = OrderedDict()        # ip -> {"at": ts, "attack": str, "auto": bool}
        self._lock    = threading.Lock()
        self._running = True
        self._on_change = on_change          # callback fired after any state change

        # Start auto-unblock thread
        self._thread = threading.Thread(target=self._auto_unblock_loop, daemon=True)
        self._thread.start()

    # ── Public API ─────────────────────────────────────────────────

    def block(self, ip: str, attack_type: str = "manual", auto: bool = True) -> bool:
        """
        Add iptables DROP rule for ip. Returns True if newly blocked, False if already blocked or whitelisted.
        """
        if ip in WHITELIST:
            return False

        with self._lock:
            if ip in self._blocked:
                # Already blocked — just refresh the timer (Option B from design)
                self._blocked[ip]["at"] = time.time()
                self._notify()
                return False

            ok = self._iptables_add(ip)
            if not ok:
                return False

            self._blocked[ip] = {
                "at":     time.time(),
                "attack": attack_type,
                "auto":   auto,
            }
            self._notify()
            return True

    def unblock(self, ip: str) -> bool:
        """Remove iptables DROP rule. Returns True if it was blocked."""
        with self._lock:
            if ip not in self._blocked:
                return False
            self._iptables_remove(ip)
            del self._blocked[ip]
            self._notify()
            return True

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def list_blocked(self) -> list:
        """Return [(ip, info_dict), ...] sorted by oldest first."""
        with self._lock:
            return list(self._blocked.items())

    def stop(self):
        """Stop the auto-unblock thread and remove all our iptables rules."""
        self._running = False
        with self._lock:
            for ip in list(self._blocked):
                self._iptables_remove(ip)
            self._blocked.clear()

    # ── Background ─────────────────────────────────────────────────

    def _auto_unblock_loop(self):
        # Blocks are permanent — auto-unblock is disabled.
        while self._running:
            time.sleep(60)

    # ── iptables wrappers ──────────────────────────────────────────

    def _iptables_add(self, ip: str) -> bool:
        # First check if rule already exists (avoid duplicates from prior run)
        try:
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if check.returncode == 0:
                return True   # already in iptables, count it as blocked
        except FileNotFoundError:
            print("[enforcer] iptables not found")
            return False

        try:
            r = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            if r.returncode != 0:
                print(f"[enforcer] block failed for {ip}: {r.stderr.decode().strip()}")
                return False
        except Exception as e:
            print(f"[enforcer] block error for {ip}: {e}")
            return False

        return True

    def _iptables_remove(self, ip: str):
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[enforcer] unblock error for {ip}: {e}")

    # ── Internal ───────────────────────────────────────────────────

    def _notify(self):
        if self._on_change:
            try:
                self._on_change()
            except Exception:
                pass
