"""
Tab 2: PCAP File Analyzer & Deep Inspector.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog
from gui.tabs.base_tab import BaseTab
from services.packet.pcap_service import (
    load_pcap_file,
    calculate_pcap_statistics,
)
from services.packet.sniffer_service import extract_packet_meta
from core.config import CAPTURES_DIR


class PcapTab(BaseTab):
    """PCAP file loading, statistical breakdown, and individual packet dissection."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.packets = []
        self.build_ui()

    def build_ui(self):
        # File selector frame
        top_bar = tk.Frame(self, bg=self.theme["bg_card"])
        top_bar.pack(fill="x", padx=10, pady=10)

        tk.Label(top_bar, text="PCAP File:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=5)
        self.entry_path = ttk.Entry(top_bar, width=45)
        default_pcap = str(CAPTURES_DIR / "sample_test.pcap")
        self.entry_path.insert(0, default_pcap)
        self.entry_path.pack(side="left", padx=5)

        ttk.Button(top_bar, text="Browse...", command=self.browse_file).pack(side="left", padx=3)
        ttk.Button(top_bar, text="📊 Load & Analyze", style="Accent.TButton", command=self.load_and_analyze).pack(side="left", padx=8)

        # Stats summary label
        self.lbl_stats = tk.Label(
            self,
            text="Load a PCAP file to view protocol distribution and top IP talkers.",
            bg=self.theme["bg_surface"],
            fg=self.theme["accent_lavender"],
            font=("DejaVu Sans", 9),
            relief="groove",
            padx=10,
            pady=8,
            justify="left",
        )
        self.lbl_stats.pack(fill="x", padx=10, pady=(0, 10))

        # Packets Table
        cols = ("#", "Source", "Destination", "Protocol", "Summary")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("#", width=50, anchor="center")
        self.tree.column("Source", width=140)
        self.tree.column("Destination", width=140)
        self.tree.column("Protocol", width=80, anchor="center")
        self.tree.column("Summary", width=420)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.tree.bind("<Double-1>", self.on_double_click)

    def browse_file(self):
        chosen = filedialog.askopenfilename(
            initialdir=str(CAPTURES_DIR),
            filetypes=[("PCAP files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")],
        )
        if chosen:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, chosen)

    def load_and_analyze(self):
        path = self.entry_path.get().strip()
        if not os.path.exists(path):
            self.log(f"[-] PCAP file not found: {path}")
            return

        self.log(f"[*] Loading and analyzing PCAP file: {path} ...")
        for r in self.tree.get_children():
            self.tree.delete(r)

        self.run_async(self._worker_load, on_success=self._on_load_done, filepath=path)

    def _worker_load(self, filepath: str):
        packets = load_pcap_file(filepath)
        stats = calculate_pcap_statistics(packets)
        return packets, stats

    def _on_load_done(self, result):
        self.packets, stats = result
        total = stats["total_packets"]
        protos = ", ".join([f"{k}: {v}" for k, v in stats["protocol_counts"].items()])
        top_ips = ", ".join([f"{ip} ({cnt})" for ip, cnt in stats["top_ips"][:4]])

        summary_text = (
            f"📦 Total Packets: {total}  |  📊 Protocols: {protos}\n"
            f"🌐 Top Talkers: {top_ips or 'N/A'}"
        )
        self.lbl_stats.config(text=summary_text)

        # Fill table (up to 500 for performance)
        for i, pkt in enumerate(self.packets[:500]):
            meta = extract_packet_meta(pkt, index=i)
            self.tree.insert("", "end", values=(meta["index"], meta["src"], meta["dst"], meta["proto"], meta["info"]))

        self.log(f"[+] Loaded {total} packets successfully. Double-click any packet for deep .show() dissection.")

    def on_double_click(self, event):
        item = self.tree.selection()
        if item:
            vals = self.tree.item(item[0], "values")
            idx = int(vals[0])
            if 0 <= idx < len(self.packets):
                self.show_packet_dialog(self.packets[idx], title=f"PCAP Packet #{idx}")
