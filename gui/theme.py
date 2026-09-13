"""
Catppuccin Mocha Dark Theme & TTK Styles for Scapy Network Toolkit.
"""

import tkinter as tk
from tkinter import ttk

# Catppuccin Mocha Palette
THEME = {
    "bg_dark": "#181825",
    "bg_card": "#1e1e2e",
    "bg_surface": "#313244",
    "bg_crust": "#11111b",
    "fg_text": "#cdd6f4",
    "fg_subtext": "#a6adc8",
    "accent_blue": "#89b4fa",
    "accent_green": "#a6e3a1",
    "accent_red": "#f38ba8",
    "accent_yellow": "#f9e2af",
    "accent_lavender": "#b4befe",
    "accent_peach": "#fab387",
}


def apply_theme(root: tk.Tk):
    """Applies modern dark palette and custom widget styles to Tk/ttk."""
    root.configure(bg=THEME["bg_dark"])

    style = ttk.Style()
    style.theme_use("clam")

    # Global TTK defaults
    style.configure(
        ".",
        background=THEME["bg_card"],
        foreground=THEME["fg_text"],
        font=("DejaVu Sans", 10),
    )

    # Notebook & Tabs
    style.configure("TNotebook", background=THEME["bg_dark"], tabmargins=[2, 5, 2, 0])
    style.configure(
        "TNotebook.Tab",
        background=THEME["bg_card"],
        foreground=THEME["fg_text"],
        padding=[12, 6],
        font=("DejaVu Sans", 10, "bold"),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", THEME["accent_blue"]), ("active", THEME["bg_surface"])],
        foreground=[("selected", THEME["bg_crust"]), ("active", "#ffffff")],
    )

    # Buttons
    style.configure(
        "TButton",
        background=THEME["bg_surface"],
        foreground=THEME["fg_text"],
        padding=6,
        relief="flat",
        font=("DejaVu Sans", 9, "bold"),
    )
    style.map(
        "TButton",
        background=[("active", THEME["accent_blue"])],
        foreground=[("active", THEME["bg_crust"])],
    )

    style.configure(
        "Accent.TButton",
        background=THEME["accent_blue"],
        foreground=THEME["bg_crust"],
        padding=6,
        font=("DejaVu Sans", 9, "bold"),
    )
    style.map("Accent.TButton", background=[("active", THEME["accent_lavender"])])

    style.configure(
        "Danger.TButton",
        background=THEME["accent_red"],
        foreground=THEME["bg_crust"],
        padding=6,
        font=("DejaVu Sans", 9, "bold"),
    )
    style.map("Danger.TButton", background=[("active", "#eba0ac")])

    # Treeview (Data Tables)
    style.configure(
        "Treeview",
        background=THEME["bg_crust"],
        foreground=THEME["fg_text"],
        fieldbackground=THEME["bg_crust"],
        rowheight=24,
    )
    style.configure(
        "Treeview.Heading",
        background=THEME["bg_surface"],
        foreground=THEME["accent_blue"],
        font=("DejaVu Sans", 9, "bold"),
    )
    style.map("Treeview", background=[("selected", THEME["accent_blue"])], foreground=[("selected", THEME["bg_crust"])])

    # Combobox & Entry
    style.configure("TCombobox", fieldbackground=THEME["bg_crust"], foreground=THEME["fg_text"])
    style.configure("TEntry", fieldbackground=THEME["bg_crust"], foreground=THEME["fg_text"])
    style.configure("TCheckbutton", background=THEME["bg_card"], foreground=THEME["fg_text"])
    style.configure("TRadiobutton", background=THEME["bg_card"], foreground=THEME["fg_text"])
