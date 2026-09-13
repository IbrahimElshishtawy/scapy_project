"""
Deep Packet Dissection Dialog (.show()).
"""

import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from gui.theme import THEME
from services.packet.pcap_service import dissect_packet_details


class PacketDissectionDialog(tk.Toplevel):
    """Modal popup dialog showing complete layer-by-layer packet dissection."""

    def __init__(self, parent, packet, packet_title: str = "Packet Inspection"):
        super().__init__(parent)
        self.title(f"🔬 {packet_title} - Scapy .show() Dissection")
        self.geometry("780x560")
        self.configure(bg=THEME["bg_dark"])

        header = tk.Frame(self, bg=THEME["bg_crust"], height=40)
        header.pack(fill="x", side="top")

        tk.Label(
            header,
            text=f"🔬 {packet_title}",
            fg=THEME["accent_blue"],
            bg=THEME["bg_crust"],
            font=("DejaVu Sans", 11, "bold"),
        ).pack(side="left", padx=15, pady=8)

        text_box = ScrolledText(
            self,
            bg=THEME["bg_crust"],
            fg=THEME["accent_green"],
            font=("DejaVu Sans Mono", 10),
            insertbackground="white",
            relief="flat",
        )
        text_box.pack(fill="both", expand=True, padx=12, pady=10)

        details = dissect_packet_details(packet)
        text_box.insert(tk.END, details)
        text_box.configure(state="disabled")

        btn_row = tk.Frame(self, bg=THEME["bg_dark"])
        btn_row.pack(fill="x", side="bottom", padx=12, pady=(0, 10))

        ttk.Button(btn_row, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(
            btn_row,
            text="Copy to Clipboard",
            command=lambda: self._copy_to_clipboard(details),
        ).pack(side="right", padx=6)

    def _copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
