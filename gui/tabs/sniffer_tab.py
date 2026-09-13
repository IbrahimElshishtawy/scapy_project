"""
Tab 1: Live Packet Sniffer & PCAP Exporter.
"""

import tkinter as tk
from tkinter import ttk
from datetime import datetime
from gui.tabs.base_tab import BaseTab
from services.packet.sniffer_service import (
    capture_packets,
    extract_packet_meta,
    save_packets_to_pcap,
)
from core.config import CAPTURES_DIR


class SnifferTab(BaseTab):
    """Live packet capture with BPF filtering, Treeview display, and PCAP export."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.is_sniffing = False
        self.captured_packets = []
        self.build_ui()

    def build_ui(self):
        ctrl = tk.Frame(self, bg=self.theme["bg_card"])
        ctrl.pack(fill="x", padx=10, pady=10)

        tk.Label(ctrl, text="BPF Filter:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.combo_filter = ttk.Combobox(ctrl, values=["", "tcp", "udp", "icmp", "port 80 or port 443", "arp"], width=24)
        self.combo_filter.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(ctrl, text="Count (0=∞):", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.entry_count = ttk.Entry(ctrl, width=7)
        self.entry_count.insert(0, "0")
        self.entry_count.grid(row=0, column=3, padx=5, pady=5)

        self.var_save_pcap = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl, text="Auto-save PCAP", variable=self.var_save_pcap).grid(row=0, column=4, padx=10, pady=5)

        self.btn_toggle = ttk.Button(ctrl, text="▶ Start Sniffing", style="Accent.TButton", command=self.toggle_sniffing)
        self.btn_toggle.grid(row=0, column=5, padx=10, pady=5)

        # Table
        cols = ("#", "Source", "Destination", "Protocol", "Info")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("#", width=50, anchor="center")
        self.tree.column("Source", width=140)
        self.tree.column("Destination", width=140)
        self.tree.column("Protocol", width=80, anchor="center")
        self.tree.column("Info", width=420)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.tree.bind("<Double-1>", self.on_double_click)

    def toggle_sniffing(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.btn_toggle.config(text="⏹ Stop Sniffing", style="Danger.TButton")
            self.captured_packets.clear()
            for row in self.tree.get_children():
                self.tree.delete(row)

            filt = self.combo_filter.get().strip()
            count_val = int(self.entry_count.get().strip() or 0)
            self.log(f"[*] Sniffer started (Filter: '{filt or 'All'}')...")

            self.run_async(self._worker_sniff, on_success=self._on_sniff_done, filter_expr=filt, count=count_val)
        else:
            self.is_sniffing = False
            self.btn_toggle.config(text="▶ Start Sniffing", style="Accent.TButton")
            self.log("[*] Stopping sniffer...")

    def _worker_sniff(self, filter_expr: str, count: int):
        def _on_pkt(pkt):
            if not self.is_sniffing:
                return
            idx = len(self.captured_packets)
            self.captured_packets.append(pkt)
            meta = extract_packet_meta(pkt, index=idx)
            self.after(0, lambda m=meta: self._add_table_row(m))

        capture_packets(
            filter_expr=filter_expr,
            count=count,
            callback=_on_pkt,
            stop_filter=lambda p: not self.is_sniffing,
        )

    def _add_table_row(self, meta):
        self.tree.insert("", "end", values=(meta["index"], meta["src"], meta["dst"], meta["proto"], meta["info"]))
        # Auto-scroll
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

    def _on_sniff_done(self, _):
        self.is_sniffing = False
        self.btn_toggle.config(text="▶ Start Sniffing", style="Accent.TButton")
        total = len(self.captured_packets)
        self.log(f"[+] Sniffing session ended. Captured {total} packet(s).")
        if self.var_save_pcap.get() and total > 0:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_path = str(CAPTURES_DIR / f"gui_capture_{ts}.pcap")
            save_packets_to_pcap(self.captured_packets, pcap_path)
            self.log(f"[+] PCAP saved to: {pcap_path}")

    def on_double_click(self, event):
        item = self.tree.selection()
        if item:
            vals = self.tree.item(item[0], "values")
            idx = int(vals[0])
            if 0 <= idx < len(self.captured_packets):
                self.show_packet_dialog(self.captured_packets[idx], title=f"Packet #{idx} ({vals[3]})")
