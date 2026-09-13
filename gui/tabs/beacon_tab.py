"""
Tab 8: 802.11 Wi-Fi Beacon Security Inspector.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog
from gui.tabs.base_tab import BaseTab
from services.wireless.beacon_analyzer import analyze_wireless_pcap
from core.config import CAPTURES_DIR


class BeaconTab(BaseTab):
    """802.11 Beacon management frame dissection and WPA/WPA2/WPA3 analyzer."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.build_ui()

    def build_ui(self):
        top = tk.Frame(self, bg=self.theme["bg_card"])
        top.pack(fill="x", padx=10, pady=10)

        tk.Label(top, text="Wireless PCAP:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=5)
        self.entry_path = ttk.Entry(top, width=42)
        default_pcap = str(CAPTURES_DIR / "sample_test.pcap")
        self.entry_path.insert(0, default_pcap)
        self.entry_path.pack(side="left", padx=5)

        ttk.Button(top, text="Browse...", command=self.browse_file).pack(side="left", padx=3)
        ttk.Button(top, text="🛡️ Dissect Beacons", style="Accent.TButton", command=self.do_dissect).pack(side="left", padx=8)

        # Table
        cols = ("SSID", "BSSID (MAC)", "Channel", "Encryption Profile", "Security Verdict")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("SSID", width=180)
        self.tree.column("BSSID (MAC)", width=170)
        self.tree.column("Channel", width=80, anchor="center")
        self.tree.column("Encryption Profile", width=220)
        self.tree.column("Security Verdict", width=180, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def browse_file(self):
        chosen = filedialog.askopenfilename(
            initialdir=str(CAPTURES_DIR),
            filetypes=[("PCAP files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")],
        )
        if chosen:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, chosen)

    def do_dissect(self):
        path = self.entry_path.get().strip()
        if not os.path.exists(path):
            self.log(f"[-] File not found: {path}")
            return

        self.log(f"[*] Dissecting 802.11 beacon frames from: {path} ...")
        for r in self.tree.get_children():
            self.tree.delete(r)

        self.run_async(self._worker_analyze, on_success=self._on_analyze_done, path=path)

    def _worker_analyze(self, path: str):
        return analyze_wireless_pcap(path)

    def _on_analyze_done(self, beacons):
        if not beacons:
            self.log("[-] No 802.11 Beacon frames identified in this capture file.")
            return

        for b in beacons:
            verdict = "SECURE (Modern)" if b["is_secure"] else "VULNERABLE / LEGACY"
            self.tree.insert("", "end", values=(b["ssid"], b["bssid"], b["channel"], b["encryption"], verdict))

        self.log(f"[+] Dissected {len(beacons)} unique wireless access point beacon(s).")
