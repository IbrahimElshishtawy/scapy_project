"""
Tab 4: ICMP Ping & TCP SYN Port Scanner.
"""

import tkinter as tk
from tkinter import ttk
from gui.tabs.base_tab import BaseTab
from services.scanner.port_scanner import icmp_ping, tcp_syn_scan_port
from core.config import COMMON_PORTS


class PortTab(BaseTab):
    """Host reachability and stealth TCP SYN scanning tab."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.build_ui()

    def build_ui(self):
        ctrl = tk.Frame(self, bg=self.theme["bg_card"])
        ctrl.pack(fill="x", padx=10, pady=10)

        tk.Label(ctrl, text="Target IP/Host:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_target = ttk.Entry(ctrl, width=20)
        self.entry_target.insert(0, "127.0.0.1")
        self.entry_target.grid(row=0, column=1, padx=5, pady=5)

        self.btn_ping = ttk.Button(ctrl, text="📡 Ping Test", command=self.do_ping)
        self.btn_ping.grid(row=0, column=2, padx=5, pady=5)

        tk.Label(ctrl, text="Ports (comma-separated):", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.entry_ports = ttk.Entry(ctrl, width=28)
        self.entry_ports.insert(0, "21, 22, 23, 80, 443, 3306, 8080")
        self.entry_ports.grid(row=0, column=4, padx=5, pady=5)

        self.btn_scan = ttk.Button(ctrl, text="🎯 SYN Scan", style="Accent.TButton", command=self.do_scan)
        self.btn_scan.grid(row=0, column=5, padx=8, pady=5)

        # Host status indicator
        self.lbl_host_status = tk.Label(
            self,
            text="Target Status: Unknown (Run Ping Test)",
            bg=self.theme["bg_surface"],
            fg=self.theme["accent_yellow"],
            font=("DejaVu Sans", 9, "bold"),
            padx=10,
            pady=6,
        )
        self.lbl_host_status.pack(fill="x", padx=10, pady=(0, 10))

        # Table
        cols = ("Port", "Service", "Status", "Protocol")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("Port", width=90, anchor="center")
        self.tree.column("Service", width=250)
        self.tree.column("Status", width=140, anchor="center")
        self.tree.column("Protocol", width=100, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def do_ping(self):
        target = self.entry_target.get().strip()
        self.log(f"[*] Sending ICMP Echo Request to {target}...")
        self.btn_ping.config(state="disabled")
        self.run_async(self._worker_ping, on_success=self._on_ping_done, target=target)

    def _worker_ping(self, target: str):
        return icmp_ping(target, timeout=1.5)

    def _on_ping_done(self, is_up: bool):
        self.btn_ping.config(state="normal")
        target = self.entry_target.get().strip()
        if is_up:
            self.lbl_host_status.config(text=f"● Host {target} is UP and responding to Ping!", fg=self.theme["accent_green"])
            self.log(f"[+] {target} is UP.")
        else:
            self.lbl_host_status.config(text=f"▲ Host {target} is DOWN or blocking ICMP Echo.", fg=self.theme["accent_red"])
            self.log(f"[!] {target} did not reply to Ping.")

    def do_scan(self):
        target = self.entry_target.get().strip()
        ports_str = self.entry_ports.get().strip()
        ports = []
        if ports_str:
            for p in ports_str.split(","):
                if p.strip().isdigit():
                    ports.append(int(p.strip()))
        if not ports:
            ports = sorted(list(COMMON_PORTS.keys()))

        self.log(f"[*] Starting TCP SYN scan on {target} for {len(ports)} port(s)...")
        for r in self.tree.get_children():
            self.tree.delete(r)

        self.btn_scan.config(state="disabled")
        self.run_async(self._worker_scan, on_success=self._on_scan_done, target=target, ports=ports)

    def _worker_scan(self, target: str, ports: list):
        results = []
        for port in ports:
            p, status, service = tcp_syn_scan_port(target, port, timeout=1.0)
            results.append((p, service, status, "TCP"))
            self.after(0, lambda r=(p, service, status, "TCP"): self.tree.insert("", "end", values=r))
        return results

    def _on_scan_done(self, results):
        self.btn_scan.config(state="normal")
        open_count = sum(1 for r in results if r[2] == "Open")
        self.log(f"[+] Scan completed. Found {open_count} OPEN port(s).")
