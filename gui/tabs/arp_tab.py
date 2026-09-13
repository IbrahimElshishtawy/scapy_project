"""
Tab 3: ARP Local Network Discovery Scanner.
"""

import tkinter as tk
from tkinter import ttk
from gui.tabs.base_tab import BaseTab
from services.scanner.arp_scanner import scan_network


class ArpTab(BaseTab):
    """ARP Broadcast Scanner for discovering local IP and MAC addresses."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.build_ui()

    def build_ui(self):
        ctrl = tk.Frame(self, bg=self.theme["bg_card"])
        ctrl.pack(fill="x", padx=10, pady=10)

        tk.Label(ctrl, text="Subnet CIDR:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=5)
        self.entry_subnet = ttk.Entry(ctrl, width=22)
        self.entry_subnet.insert(0, "192.168.1.0/24")
        self.entry_subnet.pack(side="left", padx=5)

        tk.Label(ctrl, text="Timeout (sec):", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=5)
        self.entry_timeout = ttk.Entry(ctrl, width=6)
        self.entry_timeout.insert(0, "2")
        self.entry_timeout.pack(side="left", padx=5)

        self.btn_scan = ttk.Button(ctrl, text="🔍 Scan Network", style="Accent.TButton", command=self.start_scan)
        self.btn_scan.pack(side="left", padx=10)

        self.progress = ttk.Progressbar(ctrl, mode="indeterminate", length=140)

        # Table
        cols = ("#", "IP Address", "MAC Address", "Vendor / Info")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("#", width=50, anchor="center")
        self.tree.column("IP Address", width=180)
        self.tree.column("MAC Address", width=220)
        self.tree.column("Vendor / Info", width=280)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def start_scan(self):
        subnet = self.entry_subnet.get().strip()
        timeout = int(self.entry_timeout.get().strip() or 2)
        self.log(f"[*] Sending ARP broadcast to {subnet} (timeout={timeout}s)...")

        for r in self.tree.get_children():
            self.tree.delete(r)

        self.btn_scan.config(state="disabled")
        self.progress.pack(side="left", padx=5)
        self.progress.start(10)

        self.run_async(self._worker_scan, on_success=self._on_scan_done, subnet=subnet, timeout=timeout)

    def _worker_scan(self, subnet: str, timeout: int):
        return scan_network(subnet, timeout=timeout)

    def _on_scan_done(self, devices):
        self.progress.stop()
        self.progress.pack_forget()
        self.btn_scan.config(state="normal")

        for i, dev in enumerate(devices):
            self.tree.insert("", "end", values=(i + 1, dev["ip"], dev["mac"], "Active Host"))

        self.log(f"[+] ARP discovery complete. Found {len(devices)} active host(s).")
