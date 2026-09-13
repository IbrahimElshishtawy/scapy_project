"""
Tab 7: Router Gateway Auto-Discovery & Service Scanner.
"""

import tkinter as tk
from tkinter import ttk
from gui.tabs.base_tab import BaseTab
from services.scanner.gateway_scanner import (
    get_default_gateway,
    scan_router_ports,
    evaluate_router_security,
)
from services.scanner.port_scanner import icmp_ping


class GatewayTab(BaseTab):
    """Router gateway auto-discovery and sensitive service scanning tab."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.build_ui()

    def build_ui(self):
        ctrl = tk.Frame(self, bg=self.theme["bg_card"])
        ctrl.pack(fill="x", padx=10, pady=10)

        ttk.Button(ctrl, text="🚀 Auto-Detect Gateway", style="Accent.TButton", command=self.auto_detect).pack(side="left", padx=5)

        tk.Label(ctrl, text="Gateway IP:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=5)
        self.entry_gw = ttk.Entry(ctrl, width=18)
        self.entry_gw.pack(side="left", padx=5)

        self.btn_scan = ttk.Button(ctrl, text="🎯 Scan Router Services", command=self.do_scan)
        self.btn_scan.pack(side="left", padx=8)

        # Gateway Info Card
        self.lbl_info = tk.Label(
            self,
            text="Press 'Auto-Detect Gateway' to discover current router IP and interface.",
            bg=self.theme["bg_surface"],
            fg=self.theme["accent_lavender"],
            font=("DejaVu Sans", 9),
            padx=10,
            pady=6,
        )
        self.lbl_info.pack(fill="x", padx=10, pady=(0, 10))

        # Table
        cols = ("Port", "Service Name", "Status", "Security Assessment")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=13)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("Port", width=90, anchor="center")
        self.tree.column("Service Name", width=250)
        self.tree.column("Status", width=120, anchor="center")
        self.tree.column("Security Assessment", width=340)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def auto_detect(self):
        self.log("[*] Detecting default gateway from routing table...")
        gw_ip, local_ip, iface = get_default_gateway()
        if gw_ip:
            self.entry_gw.delete(0, tk.END)
            self.entry_gw.insert(0, gw_ip)
            self.lbl_info.config(
                text=f"🌐 Router IP: {gw_ip}  |  💻 Local IP: {local_ip or 'Unknown'}  |  🔌 Interface: {iface or 'Unknown'}"
            )
            self.log(f"[+] Gateway detected: {gw_ip} on {iface}")
        else:
            self.lbl_info.config(text="[-] Could not detect Gateway. Please check network connection or enter IP manually.")
            self.log("[-] Could not automatically detect gateway.")

    def do_scan(self):
        gw = self.entry_gw.get().strip()
        if not gw:
            self.auto_detect()
            gw = self.entry_gw.get().strip()
            if not gw:
                return

        self.log(f"[*] Starting targeted router scan on {gw}...")
        for r in self.tree.get_children():
            self.tree.delete(r)

        self.btn_scan.config(state="disabled")
        self.run_async(self._worker_scan, on_success=self._on_scan_done, gw=gw)

    def _worker_scan(self, gw: str):
        is_up = icmp_ping(gw, timeout=1.5)
        results = scan_router_ports(gw, timeout=1.0)
        alerts = evaluate_router_security(results)
        return is_up, results, alerts

    def _on_scan_done(self, result):
        self.btn_scan.config(state="normal")
        is_up, results, alerts = result

        for r in results:
            note = "Standard Service"
            if r["port"] == 23 and r["status"] == "Open":
                note = "CRITICAL: Insecure Telnet Exposed!"
            elif r["port"] == 7547 and r["status"] == "Open":
                note = "WARNING: CWMP / TR-069 Management Active"
            elif r["port"] == 80 and r["status"] == "Open":
                note = "Router Web Administration UI"

            self.tree.insert("", "end", values=(r["port"], r["service"], r["status"], note))

        for alert in alerts:
            self.log(alert)
