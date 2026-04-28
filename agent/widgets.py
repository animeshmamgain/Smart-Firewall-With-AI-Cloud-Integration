"""
widgets.py — Themed widget factories.
"""

import customtkinter as ctk
from config import THEME


# ── Color helpers ────────────────────────────────────────────────

def _hex_to_rgb(h: str):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def tint(color: str, amount: float = 0.15, base: str = None) -> str:
    """
    Blend `color` with the panel background by `amount` (0..1).
    Returns a 6-digit hex Tk accepts, never 8-digit.
    Used for hover effects.
    """
    base = base or THEME["panel"]
    fg = _hex_to_rgb(color)
    bg = _hex_to_rgb(base)
    blended = tuple(int(b + (f - b) * amount) for f, b in zip(fg, bg))
    return _rgb_to_hex(blended)


# ── Panels ───────────────────────────────────────────────────────

def make_panel(parent, **kwargs) -> ctk.CTkFrame:
    return ctk.CTkFrame(
        parent,
        fg_color=THEME["panel"],
        border_color=THEME["border"],
        border_width=1,
        corner_radius=6,
        **kwargs,
    )


def make_section_header(parent, text: str, color: str = None) -> ctk.CTkLabel:
    color = color or THEME["accent"]
    lbl = ctk.CTkLabel(
        parent, text=f" ▸ {text}",
        font=THEME["font_header"], text_color=color, anchor="w",
    )
    lbl.pack(fill="x", padx=12, pady=(10, 6))
    return lbl


# ── Buttons ──────────────────────────────────────────────────────

def make_button(parent, text: str, command, color: str = None, width: int = 130, **kwargs) -> ctk.CTkButton:
    color = color or THEME["accent"]
    return ctk.CTkButton(
        parent, text=text, command=command,
        fg_color="transparent",
        border_color=color, border_width=1,
        hover_color=tint(color, 0.20),
        text_color=color,
        font=("Courier New", 11, "bold"),
        corner_radius=4,
        width=width, height=32,
        **kwargs,
    )


# ── Entries ──────────────────────────────────────────────────────

def make_entry(parent, placeholder: str = "", **kwargs) -> ctk.CTkEntry:
    return ctk.CTkEntry(
        parent, placeholder_text=placeholder,
        font=THEME["font_mono"],
        fg_color=THEME["bg"], border_color=THEME["border"],
        text_color=THEME["text"], height=32, corner_radius=4,
        **kwargs,
    )


# ── Labels ───────────────────────────────────────────────────────

def make_label(parent, text: str, color: str = None, font=None, **kwargs) -> ctk.CTkLabel:
    return ctk.CTkLabel(
        parent, text=text,
        font=font or THEME["font_mono"],
        text_color=color or THEME["text"],
        **kwargs,
    )


# ── Separator ────────────────────────────────────────────────────

def make_separator(parent, vertical: bool = False, **kwargs) -> ctk.CTkFrame:
    if vertical:
        return ctk.CTkFrame(parent, fg_color=THEME["border"], width=1, corner_radius=0, **kwargs)
    return ctk.CTkFrame(parent, fg_color=THEME["border"], height=1, corner_radius=0, **kwargs)
