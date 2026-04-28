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
