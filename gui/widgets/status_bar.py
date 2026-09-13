"""
Header & Privilege Status Bar Widget.
"""

import tkinter as tk
from gui.theme import THEME
from core.privileges import is_root


class HeaderStatusBar(tk.Frame):
    """Header bar with project title and root privilege indicator."""

    def __init__(self, parent):
        super().__init__(parent, bg=THEME["bg_crust"], height=50)
        self.pack(fill="x", side="top")

        title_lbl = tk.Label(
            self,
            text="🛡️ SCAPY NETWORK TOOLKIT & SUITE (v2.0)",
            font=("DejaVu Sans", 13, "bold"),
            fg=THEME["accent_blue"],
            bg=THEME["bg_crust"],
        )
        title_lbl.pack(side="left", padx=15, pady=10)

        self.privilege_lbl = tk.Label(
            self,
            text="Checking Privileges...",
            font=("DejaVu Sans", 9, "bold"),
            bg=THEME["bg_crust"],
        )
        self.privilege_lbl.pack(side="right", padx=15)
        self.update_privilege_badge()

    def update_privilege_badge(self):
        if is_root():
            self.privilege_lbl.config(
                text="● ROOT: PERMITTED (Superuser)",
                fg=THEME["accent_green"],
            )
        else:
            self.privilege_lbl.config(
                text="▲ USER MODE (Sudo recommended for Sniffer)",
                fg=THEME["accent_yellow"],
            )
