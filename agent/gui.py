"""
gui.py - Tab-based firewall agent UI.

Header:    title, AI status, mode toggle
Tabs:      ALERTS | PENDING | BLOCKED | DETECTOR
Footer:    manual block control (always visible, primary user action)

Right-click any row for context actions.
"""

import time
import tkinter as tk
import customtkinter as ctk
from tkinter import ttk

from config            import THEME, DEFAULT_MODE, AUTO_UNBLOCK_SECONDS, GUI_REFRESH_INTERVAL
from enforcer          import Enforcer
from event_consumer    import EventConsumer
from database          import Database
from detector_runner   import DetectorRunner
from alert_store       import AlertStore
from widgets           import (make_panel, make_section_header, make_button,
                               make_entry, make_label, tint)
from dialogs           import confirm, info, show_alert_detail
import cloud_hooks


class FirewallAgentUI:
    def __init__(self):
        self.mode   = DEFAULT_MODE
        self._dirty = True

        # Backend
        self.db        = Database()
        self.enforcer  = Enforcer(on_change=self._mark_dirty)
        self.consumer  = EventConsumer(on_event=self._handle_event)
        self.runner    = DetectorRunner()
        self.store     = AlertStore()

        # Root
        ctk.set_appearance_mode("dark")
        self.root = ctk.CTk()
        self.root.title("Smart Firewall Agent")
        self.root.geometry("1280x820")
        self.root.minsize(1200, 760)
        self.root.configure(fg_color=THEME["bg"])

        self._build_ui()
        self._configure_treeview_style()

        self.consumer.start()
        self.runner.start()
        self.root.after(GUI_REFRESH_INTERVAL, self._refresh_loop)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- UI construction --------------------------------------------

    def _build_ui(self):
        self._build_header()
        self._build_tabs()
        self._build_footer()

    def _build_header(self):
        hdr = ctk.CTkFrame(self.root, fg_color=THEME["panel"],
                           border_color=THEME["accent"], border_width=1,
                           corner_radius=0, height=60)
        hdr.pack(fill="x"); hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text="\u25c6 SMART FIREWALL AGENT",
                     font=("Courier New", 20, "bold"),
                     text_color=THEME["accent"]).pack(side="left", padx=22)

        # AI status
        self.ai_status_lbl = ctk.CTkLabel(
            hdr, text="\u25cf AI: starting...",
            font=("Courier New", 12, "bold"),
            text_color=THEME["text_dim"],
        )
        self.ai_status_lbl.pack(side="right", padx=20)

        # Mode segmented control
        mode_box = ctk.CTkFrame(hdr, fg_color="transparent")
        mode_box.pack(side="right", padx=14)
        make_label(mode_box, "MODE:", color=THEME["text_dim"],
                   font=("Courier New", 10, "bold")).pack(side="left", padx=(0, 10))
        self.mode_seg = ctk.CTkSegmentedButton(
            mode_box, values=["AUTO", "MANUAL"],
            command=self._mode_changed,
            font=("Courier New", 11, "bold"),
            selected_color=THEME["accent"],
            selected_hover_color=tint(THEME["accent"], 0.30),
            unselected_color=THEME["panel2"],
            unselected_hover_color=THEME["border"],
            text_color=THEME["text"],
            height=32,
        )
        self.mode_seg.set("AUTO" if self.mode == "auto" else "MANUAL")
        self.mode_seg.pack(side="left")

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(
            self.root,
            fg_color=THEME["panel"],
            segmented_button_fg_color=THEME["panel2"],
            segmented_button_selected_color=THEME["accent"],
            segmented_button_selected_hover_color=tint(THEME["accent"], 0.30),
            segmented_button_unselected_color=THEME["panel2"],
            segmented_button_unselected_hover_color=THEME["border"],
            text_color=THEME["text"],
            text_color_disabled=THEME["text_dim"],
            border_color=THEME["border"], border_width=1,
            corner_radius=6,
        )
        self.tabs.pack(fill="both", expand=True, padx=14, pady=10)

        for name in ("ALERTS", "PENDING", "BLOCKED", "DETECTOR"):
            self.tabs.add(name)

        self._build_alerts_tab(self.tabs.tab("ALERTS"))
        self._build_pending_tab(self.tabs.tab("PENDING"))
        self._build_blocked_tab(self.tabs.tab("BLOCKED"))
        self._build_detector_tab(self.tabs.tab("DETECTOR"))

    # -- Tab: Alerts ------------------------------------------------

    def _build_alerts_tab(self, parent):
        cols = ("time", "src_ip", "attack", "conf", "src", "status")
        widths   = {"time": 110, "src_ip": 180, "attack": 200, "conf": 110, "src": 110, "status": 140}
        anchors  = {"time": "center", "src_ip": "w", "attack": "w",
                    "conf": "center", "src": "center", "status": "center"}
        headings = {"time": "TIME", "src_ip": "SOURCE IP", "attack": "ATTACK",
                    "conf": "CONFIDENCE", "src": "DETECT", "status": "STATUS"}
        self.alerts_tree = ttk.Treeview(parent, columns=cols, show="headings", height=16)
        for c in cols:
            self.alerts_tree.heading(c, text=headings[c], anchor=anchors[c])
            self.alerts_tree.column(c, width=widths[c], anchor=anchors[c])
        self.alerts_tree.pack(fill="both", expand=True, padx=14, pady=14)

        self.alerts_tree.bind("<Double-Button-1>", self._on_alert_double_click)
        self.alerts_tree.bind("<Button-3>", self._on_alert_right_click)

        make_label(parent,
            "  Tip: double-click for details   |   right-click for more actions",
            color=THEME["text_dim"], font=("Courier New", 11),
        ).pack(fill="x", padx=18, pady=(0, 12))

    # -- Tab: Pending -----------------------------------------------

    def _build_pending_tab(self, parent):
        cols = ("time", "src_ip", "attack", "conf")
        widths   = {"time": 140, "src_ip": 220, "attack": 260, "conf": 140}
        anchors  = {"time": "center", "src_ip": "w", "attack": "w", "conf": "center"}
        headings = {"time": "TIME", "src_ip": "SOURCE IP", "attack": "ATTACK", "conf": "CONFIDENCE"}
        self.pending_tree = ttk.Treeview(parent, columns=cols, show="headings", height=14)
        for c in cols:
            self.pending_tree.heading(c, text=headings[c], anchor=anchors[c])
            self.pending_tree.column(c, width=widths[c], anchor=anchors[c])
        self.pending_tree.pack(fill="both", expand=True, padx=14, pady=14)

        self.pending_tree.bind("<Double-Button-1>", self._on_pending_double_click)
        self.pending_tree.bind("<Button-3>", self._on_pending_right_click)

        action_row = ctk.CTkFrame(parent, fg_color="transparent")
        action_row.pack(fill="x", padx=16, pady=(0, 14))
        make_button(action_row, "\u2713 APPROVE",     self._approve_selected, color=THEME["ok"]).pack(side="left", padx=4)
        make_button(action_row, "\u2717 DISMISS",     self._dismiss_selected, color=THEME["text_dim"]).pack(side="left", padx=4)
        make_button(action_row, "DISMISS ALL",        self._dismiss_all,      color=THEME["text_dim"]).pack(side="right", padx=4)

    # -- Tab: Blocked -----------------------------------------------

    def _build_blocked_tab(self, parent):
        cols = ("ip", "attack", "type", "remaining")
        widths   = {"ip": 220, "attack": 240, "type": 160, "remaining": 160}
        anchors  = {"ip": "w", "attack": "w", "type": "center", "remaining": "center"}
        headings = {"ip": "IP ADDRESS", "attack": "ATTACK", "type": "BLOCKED BY", "remaining": "REMAINING"}
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

    # -- Tab: Detector ----------------------------------------------

    def _build_detector_tab(self, parent):
        info_row = ctk.CTkFrame(parent, fg_color="transparent")
        info_row.pack(fill="x", padx=16, pady=(14, 8))
        make_label(info_row, "  Live output from the AI detector subprocess:",
                   color=THEME["text_dim"], font=("Courier New", 11),
                   ).pack(side="left")

        self.log_text = ctk.CTkTextbox(
            parent, font=("Courier New", 12),
            fg_color=THEME["panel2"], text_color=THEME["text"],
            scrollbar_button_color=THEME["border"], corner_radius=4,
        )
        self.log_text.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.log_text.configure(state="disabled")

    # -- Footer -----------------------------------------------------

    def _build_footer(self):
        footer = ctk.CTkFrame(self.root, fg_color=THEME["panel"],
                              border_color=THEME["border"], border_width=1,
                              corner_radius=0, height=64)
        footer.pack(fill="x", side="bottom"); footer.pack_propagate(False)

        make_label(footer, "  Quick block:", color=THEME["text_dim"],
                   font=("Courier New", 11)).pack(side="left", padx=(16, 6))

        self.ip_entry = make_entry(footer, "Enter IP, e.g. 192.168.1.50", width=240)
        self.ip_entry.pack(side="left", padx=4)
        self.ip_entry.bind("<Return>", lambda e: self._manual_block())

        make_button(footer, "\U0001F512 BLOCK",   self._manual_block,   color=THEME["danger"], width=110).pack(side="left", padx=4)
        make_button(footer, "\U0001F513 UNBLOCK", self._manual_unblock, color=THEME["ok"],     width=110).pack(side="left", padx=4)

        make_button(footer, "CLEAR HISTORY", self._clear_history,
                    color=THEME["text_dim"], width=130).pack(side="right", padx=14)

    # -- Style ------------------------------------------------------

    def _configure_treeview_style(self):
        style = ttk.Style(); style.theme_use("default")
        style.configure("Treeview",
            background=THEME["panel2"], foreground=THEME["text"],
            fieldbackground=THEME["panel2"], borderwidth=0,
            font=("Courier New", 12), rowheight=32)
        style.configure("Treeview.Heading",
            background=THEME["panel"], foreground=THEME["accent"],
            font=("Courier New", 12, "bold"), borderwidth=0, relief="flat",
            padding=(8, 6))
        style.map("Treeview",
            background=[("selected", THEME["accent"])],
            foreground=[("selected", THEME["bg"])])

    # -- Event handler ---------------------------------------------

    def _handle_event(self, event: dict):
        self.db.log_alert(event)
        cloud_hooks.push_alert(event)

        ip = event.get("src_ip", "")
        attack = event.get("attack_type", "unknown")

        # Already blocked: refresh timer, record, skip queue
        if self.enforcer.is_blocked(ip):
            self.enforcer.block(ip, attack_type=attack, auto=True)
            self.store.add(event, "ALREADY_BLOCKED")
            self._dirty = True
            return

        if self.mode == "auto":
            if self.enforcer.block(ip, attack_type=attack, auto=True):
                self.db.log_action("block", ip, "auto", attack)
                cloud_hooks.push_block(ip, attack, AUTO_UNBLOCK_SECONDS)
                status = "BLOCKED"
            else:
                status = "EXISTING"
        else:
            status = "PENDING"

        self.store.add(event, status)
        self._dirty = True

    # -- Actions ----------------------------------------------------

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

        menu = tk.Menu(self.root, tearoff=0,
                       bg=THEME["panel"], fg=THEME["text"],
                       activebackground=THEME["accent"], activeforeground=THEME["bg"],
                       borderwidth=0)
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

    def _on_pending_double_click(self, _event):
        sel = self.pending_tree.selection()
        if not sel: return
        tags = self.pending_tree.item(sel[0])["tags"]
        if not tags: return
        record = self.store.find(tags[0])
        if record:
            show_alert_detail(self.root, record)

    def _on_pending_right_click(self, event):
        row = self.pending_tree.identify_row(event.y)
        if not row: return
        self.pending_tree.selection_set(row)
        tags = self.pending_tree.item(row)["tags"]
        if not tags: return
        record = self.store.find(tags[0])
        if not record: return

        menu = tk.Menu(self.root, tearoff=0,
                       bg=THEME["panel"], fg=THEME["text"],
                       activebackground=THEME["accent"], activeforeground=THEME["bg"],
                       borderwidth=0)
        menu.add_command(label="View Details", command=lambda: show_alert_detail(self.root, record))
        menu.add_separator()
        menu.add_command(label="Approve", command=self._approve_selected)
        menu.add_command(label="Dismiss", command=self._dismiss_selected)
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

        menu = tk.Menu(self.root, tearoff=0,
                       bg=THEME["panel"], fg=THEME["text"],
                       activebackground=THEME["accent"], activeforeground=THEME["bg"],
                       borderwidth=0)
        menu.add_command(label=f"Unblock {ip}", command=lambda: self._unblock_ip(ip))
        menu.add_command(label="Copy IP",       command=lambda: self._copy_to_clipboard(ip))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _block_ip(self, ip: str, attack: str = "manual"):
        if self.enforcer.block(ip, attack_type=attack, auto=False):
            self.db.log_action("block", ip, "manual", attack)
            cloud_hooks.push_block(ip, attack, AUTO_UNBLOCK_SECONDS)

    def _unblock_ip(self, ip: str):
        if self.enforcer.unblock(ip):
            self.db.log_action("unblock", ip, "manual")

    def _copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _approve_selected(self):
        sel = self.pending_tree.selection()
        if not sel:
            info(self.root, "Approve", "Select a pending alert first."); return
        tags = self.pending_tree.item(sel[0])["tags"]
        if not tags: return
        record = self.store.find(tags[0])
        if not record: return

        ev = record["event"]
        ip = ev.get("src_ip", "")
        attack = ev.get("attack_type", "unknown")

        self.store.approve(tags[0])
        if self.enforcer.block(ip, attack_type=attack, auto=False):
            self.db.log_action("block", ip, "manual_approve", attack)
            cloud_hooks.push_block(ip, attack, AUTO_UNBLOCK_SECONDS)

        # Auto-resolve other pending alerts for the same IP
        for r in list(self.store.list_pending()):
            if r["event"].get("src_ip") == ip:
                self.store.dismiss(r["id"])

        self._dirty = True

    def _dismiss_selected(self):
        sel = self.pending_tree.selection()
        if not sel:
            info(self.root, "Dismiss", "Select a pending alert first."); return
        tags = self.pending_tree.item(sel[0])["tags"]
        if not tags: return
        self.store.dismiss(tags[0])
        self._dirty = True

    def _dismiss_all(self):
        n = len(self.store.list_pending())
        if n == 0: return
        if confirm(self.root, "Dismiss All Pending",
                   f"Dismiss {n} pending alert(s) without action?"):
            self.store.clear_pending()
            self._dirty = True

    def _manual_block(self):
        ip = self.ip_entry.get().strip()
        if not ip: return
        if self.enforcer.block(ip, attack_type="manual", auto=False):
            self.db.log_action("block", ip, "manual")
            cloud_hooks.push_block(ip, "manual", AUTO_UNBLOCK_SECONDS)
            self.ip_entry.delete(0, "end")
        else:
            info(self.root, "Block", f"Could not block {ip}.\nAlready blocked or whitelisted.")

    def _manual_unblock(self):
        ip = self.ip_entry.get().strip()
        if not ip: return
        if self.enforcer.unblock(ip):
            self.db.log_action("unblock", ip, "manual")
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

    def _unblock_all(self):
        n = len(self.enforcer.list_blocked())
        if n == 0: return
        if confirm(self.root, "Unblock All",
                   f"Release ALL {n} blocked IP(s)?\nThis cannot be undone.", danger=True):
            for ip, _info in list(self.enforcer.list_blocked()):
                self.enforcer.unblock(ip)
                self.db.log_action("unblock", ip, "manual_all")
            self._dirty = True

    def _clear_history(self):
        if confirm(self.root, "Clear History",
                   "Wipe ALL alert and action history?\n"
                   "This deletes the SQLite log permanently.\n"
                   "(Active blocks are preserved.)", danger=True):
            self.db.close()
            from config import DB_FILE
            try: DB_FILE.unlink()
            except Exception: pass
            self.db = Database()
            self.store.clear_all()
            self._dirty = True

    def _mode_changed(self, value):
        self.mode = "auto" if value == "AUTO" else "manual"

    # -- Refresh ----------------------------------------------------

    def _mark_dirty(self):
        self._dirty = True

    def _refresh_loop(self):
        if self._dirty:
            self._refresh_alerts()
            self._refresh_pending()
            self._refresh_blocked()
        self._refresh_log()
        self._refresh_ai_status()
        self._apply_peer_blocks()   # ← Firebase peer sync
        self._dirty = False
        self.root.after(GUI_REFRESH_INTERVAL, self._refresh_loop)

    def _apply_peer_blocks(self):
        """
        Pull peer-shared blocks from Firebase and apply them locally.
        Only blocks IPs that are not already blocked and not whitelisted.
        """
        try:
            peer_ips = cloud_hooks.fetch_blocklist()
            for ip in peer_ips:
                if not self.enforcer.is_blocked(ip):
                    newly = self.enforcer.block(ip, attack_type="peer_shared", auto=True)
                    if newly:
                        self.db.log_action("block", ip, reason="peer_shared", attack_type="peer_shared")
                        self._mark_dirty()
                        print(f"[gui] Peer block applied: {ip}")
        except Exception as e:
            print(f"[gui] _apply_peer_blocks error: {e}")

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
                r["ts"],
                ev.get("src_ip", "?"),
                ev.get("attack_type", "?"),
                f"{ev.get('confidence', 0):.2f}",
                ev.get("detection_source", "?"),
                r["status"],
            ), tags=(r["id"],))
            if r["id"] == sel_id:
                self.alerts_tree.selection_set(iid)

    def _refresh_pending(self):
        sel_id = None
        sel = self.pending_tree.selection()
        if sel:
            tags = self.pending_tree.item(sel[0])["tags"]
            if tags: sel_id = tags[0]

        for row in self.pending_tree.get_children():
            self.pending_tree.delete(row)

        for r in self.store.list_pending():
            ev = r["event"]
            iid = self.pending_tree.insert("", "end", values=(
                r["ts"],
                ev.get("src_ip", "?"),
                ev.get("attack_type", "?"),
                f"{ev.get('confidence', 0):.2f}",
            ), tags=(r["id"],))
            if r["id"] == sel_id:
                self.pending_tree.selection_set(iid)

    def _refresh_blocked(self):
        sel_ip = None
        sel = self.blocked_tree.selection()
        if sel:
            vals = self.blocked_tree.item(sel[0])["values"]
            if vals: sel_ip = vals[0]

        for row in self.blocked_tree.get_children():
            self.blocked_tree.delete(row)

        now = time.time()
        for ip, info_ in self.enforcer.list_blocked():
            elapsed = int(now - info_["at"])
            remaining = max(0, AUTO_UNBLOCK_SECONDS - elapsed)
            tag = "auto" if info_["auto"] else "manual"
            iid = self.blocked_tree.insert("", "end", values=(
                ip, info_["attack"], tag, f"{remaining}s",
            ))
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

    # -- Lifecycle --------------------------------------------------

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
