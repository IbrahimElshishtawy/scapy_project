"""
Tab: Network-Wide Port Scanner & Service Tester (Multi-Host Audit).
Enterprise Modular Architecture v2.0.
"""

import tkinter as tk
from tkinter import ttk, simpledialog
from gui.tabs.base_tab import BaseTab
from services.scanner.network_tester import (
    detect_local_network_context,
    discover_active_hosts,
    scan_and_test_host,
    DEFAULT_TEST_PORTS,
)


class NetTesterTab(BaseTab):
    """Network-wide host discovery, multi-host port scanning & service banner tester."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.ctx = detect_local_network_context()
        self.build_ui()

    def build_ui(self):
        # 1. Environment Info Header Card
        info_frame = tk.Frame(self, bg=self.theme["bg_card"], padx=10, pady=8)
        info_frame.pack(fill="x", padx=10, pady=(10, 5))

        lbl_title = tk.Label(
            info_frame,
            text="🌐 Network Environment Auto-Detection",
            bg=self.theme["bg_card"],
            fg=self.theme["accent_cyan"],
            font=("DejaVu Sans", 10, "bold"),
        )
        lbl_title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 4))

        tk.Label(
            info_frame,
            text=f"Iface: {self.ctx['iface']} | Local IP: {self.ctx['local_ip']} | Gateway: {self.ctx['gateway_ip']} ({self.ctx['gateway_mac']})",
            bg=self.theme["bg_card"],
            fg=self.theme["fg_text"],
            font=("DejaVu Sans", 9),
        ).grid(row=1, column=0, columnspan=4, sticky="w")

        # 2. Control inputs
        ctrl = tk.Frame(self, bg=self.theme["bg_surface"], padx=10, pady=8)
        ctrl.pack(fill="x", padx=10, pady=5)

        tk.Label(ctrl, text="Subnet CIDR:", bg=self.theme["bg_surface"], fg=self.theme["fg_text"]).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_subnet = ttk.Entry(ctrl, width=18)
        self.entry_subnet.insert(0, self.ctx["subnet_cidr"])
        self.entry_subnet.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(ctrl, text="Target Ports:", bg=self.theme["bg_surface"], fg=self.theme["fg_text"]).grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.entry_ports = ttk.Entry(ctrl, width=32)
        default_ports_str = ", ".join(str(p) for p in DEFAULT_TEST_PORTS[:14])
        self.entry_ports.insert(0, default_ports_str)
        self.entry_ports.grid(row=0, column=3, padx=5, pady=5)

        self.btn_audit_subnet = ttk.Button(ctrl, text="🚀 Sweep Subnet & Test Ports", style="Accent.TButton", command=self.do_audit_subnet)
        self.btn_audit_subnet.grid(row=0, column=4, padx=8, pady=5)

        self.btn_scan_target = ttk.Button(ctrl, text="🎯 Single Target Scan", command=self.do_single_target)
        self.btn_scan_target.grid(row=0, column=5, padx=5, pady=5)

        # 3. Status Bar
        self.status_bar = tk.Label(
            self,
            text="Ready. Click 'Sweep Subnet & Test Ports' to audit all active devices around you.",
            bg=self.theme["bg_card"],
            fg=self.theme["accent_yellow"],
            font=("DejaVu Sans", 9, "bold"),
            padx=10,
            pady=6,
            anchor="w",
        )
        self.status_bar.pack(fill="x", padx=10, pady=5)

        # 4. Results Treeview
        cols = ("Host IP", "MAC Address", "Port", "Service", "Latency", "Risk", "Banner / Service Details")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)

        self.tree.column("Host IP", width=120, anchor="center")
        self.tree.column("MAC Address", width=140, anchor="center")
        self.tree.column("Port", width=70, anchor="center")
        self.tree.column("Service", width=160)
        self.tree.column("Latency", width=85, anchor="center")
        self.tree.column("Risk", width=100, anchor="center")
        self.tree.column("Banner / Service Details", width=420)

        # Tags styling
        self.tree.tag_configure("high_risk", foreground="#f38ba8")
        self.tree.tag_configure("medium_risk", foreground="#fab387")
        self.tree.tag_configure("open_ok", foreground="#a6e3a1")

        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _parse_ports(self):
        ports_str = self.entry_ports.get().strip()
        ports = []
        if ports_str:
            for p in ports_str.split(","):
                if p.strip().isdigit():
                    ports.append(int(p.strip()))
        return ports or DEFAULT_TEST_PORTS

    def do_audit_subnet(self):
        subnet = self.entry_subnet.get().strip() or self.ctx["subnet_cidr"]
        ports = self._parse_ports()

        self.btn_audit_subnet.config(state="disabled")
        self.btn_scan_target.config(state="disabled")
        self.status_bar.config(
            text=f"● Step 1/2: Sweeping subnet {subnet} for live hosts...",
            fg=self.theme["accent_blue"]
        )
        self.log(f"[*] Sweeping subnet {subnet} for active devices...")

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.run_async(self._worker_audit, on_success=self._on_audit_done, subnet=subnet, ports=ports)

    def _worker_audit(self, subnet: str, ports: list):
        hosts = discover_active_hosts(subnet=subnet, timeout=2.0)
        results = []
        for h in hosts:
            open_ports = scan_and_test_host(h["ip"], ports=ports, timeout=1.0)
            results.append((h, open_ports))
        return results

    def _on_audit_done(self, results):
        self.btn_audit_subnet.config(state="normal")
        self.btn_scan_target.config(state="normal")

        total_hosts = len(results)
        total_open = 0

        for host, open_ports in results:
            hip = host["ip"]
            hmac = host["mac"]
            if host.get("is_gateway"):
                hip += " [Router]"
            elif host.get("is_local"):
                hip += " [This PC]"

            if not open_ports:
                self.tree.insert("", "end", values=(hip, hmac, "-", "No open ports", "-", "CLEAN", "All scanned ports closed/filtered"))
            else:
                for p in open_ports:
                    total_open += 1
                    tag = "open_ok"
                    if "HIGH" in p["risk_level"]:
                        tag = "high_risk"
                    elif "MEDIUM" in p["risk_level"]:
                        tag = "medium_risk"

                    self.tree.insert(
                        "",
                        "end",
                        values=(
                            hip,
                            hmac,
                            p["port"],
                            p["service"],
                            f"{p['latency_ms']} ms",
                            p["risk_level"],
                            p["banner"],
                        ),
                        tags=(tag,)
                    )

        self.status_bar.config(
            text=f"✔ Audit Complete: Found {total_hosts} live host(s) and {total_open} open service port(s).",
            fg=self.theme["accent_green"]
        )
        self.log(f"[+] Audit finished: {total_hosts} hosts, {total_open} open ports.")

    def do_single_target(self):
        target = tk.simpledialog.askstring("Target IP", "Enter IP to scan and test:", initialvalue=self.ctx["gateway_ip"])
        if not target:
            return

        ports = self._parse_ports()
        self.btn_audit_subnet.config(state="disabled")
        self.btn_scan_target.config(state="disabled")
        self.status_bar.config(text=f"● Auditing target host {target}...", fg=self.theme["accent_blue"])
        self.log(f"[*] Auditing target {target} across {len(ports)} ports...")

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.run_async(self._worker_single, on_success=self._on_single_done, target=target, ports=ports)

    def _worker_single(self, target: str, ports: list):
        return target, scan_and_test_host(target, ports=ports, timeout=1.2)

    def _on_single_done(self, res):
        target, open_ports = res
        self.btn_audit_subnet.config(state="normal")
        self.btn_scan_target.config(state="normal")

        if not open_ports:
            self.tree.insert("", "end", values=(target, "Unknown", "-", "None", "-", "CLEAN", "No open ports detected"))
        else:
            for p in open_ports:
                tag = "open_ok"
                if "HIGH" in p["risk_level"]:
                    tag = "high_risk"
                elif "MEDIUM" in p["risk_level"]:
                    tag = "medium_risk"

                self.tree.insert(
                    "",
                    "end",
                    values=(
                        target,
                        "Target Host",
                        p["port"],
                        p["service"],
                        f"{p['latency_ms']} ms",
                        p["risk_level"],
                        p["banner"],
                    ),
                    tags=(tag,)
                )

        self.status_bar.config(
            text=f"✔ Scan Complete for {target}: {len(open_ports)} open service(s) tested.",
            fg=self.theme["accent_green"]
        )
        self.log(f"[+] Target {target} scan finished: {len(open_ports)} open ports.")
