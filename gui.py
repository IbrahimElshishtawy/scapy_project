#!/usr/bin/env python3
"""
Scapy & Network Toolkit - Python Tkinter Graphical User Interface (GUI)
A full-featured, multi-tab desktop application covering all 10 tools from README.md:
1. Live Packet Sniffer & PCAP Exporter (sniff, wrpcap)
2. PCAP File Analyzer & Inspector (rdpcap, .show)
3. ARP Local Network Discovery (ARP, Ether, srp)
4. ICMP Ping & TCP SYN Port Scanner (IP, TCP, ICMP, sr1)
5. Custom Packet Crafter & Transmitter (IP, TCP, UDP, send, sendp)
6. Wi-Fi Manager & Saved Password Recovery (Scan, Passwords, Connect, Audit)
7. Router Gateway Auto-Discovery & Port Scan (Gateway detect, Services scan)
8. 802.11 Wi-Fi Beacon Security Inspector (WPA2/WPA3 Dissection)
9. HTTP & Web Reconnaissance (Requests: GET, POST, Headers, GeoIP)
10. Remote SSH & SFTP Automation (Paramiko: Connect, Exec, Audit, SFTP)
"""

import os
import sys
import time
import threading
from datetime import datetime

# Ensure modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    from tkinter.scrolledtext import ScrolledText
except ImportError:
    print("\n" + "=" * 70)
    print("[-] Error: Tkinter is not installed on your system.")
    print("    To install Tkinter on Ubuntu/Debian, please run:")
    print("    sudo apt update && sudo apt install -y python3-tk")
    print("=" * 70 + "\n")
    sys.exit(1)

# Import toolkit modules
from modules.arp_scanner import scan_network
from modules.port_scanner import icmp_ping, tcp_syn_scan_port, COMMON_PORTS
from modules.sniffer import format_packet_summary
from modules.pcap_analyzer import load_pcap, inspect_packet
from modules.packet_crafter import (
    craft_ip_tcp_packet, craft_ip_udp_packet, craft_icmp_packet,
    craft_ethernet_packet, preview_and_send
)
from modules.wifi_manager import (
    scan_nearby_wifi, get_saved_wifi_passwords, connect_to_wifi,
    audit_password_strength, calculate_entropy
)
from modules.gateway_scanner import (
    get_default_gateway, scan_router_ports, ROUTER_COMMON_SERVICES
)
from modules.wifi_sniffer import analyze_beacon_packet, analyze_wireless_pcap
from modules.http_recon import (
    check_website, audit_security_headers, ip_threat_and_geo_lookup,
    send_post_request
)
from modules.ssh_manager import RemoteSSHClient

from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, conf


class ScapyToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Scapy & Network Security Toolkit (Tkinter GUI)")
        self.root.geometry("1100x780")
        self.root.minsize(950, 650)

        # Sniffer state
        self.is_sniffing = False
        self.sniffer_thread = None
        self.captured_packets = []

        # SSH Client instance
        self.ssh_client = None

        self.setup_styles()
        self.build_ui()
        self.check_root_status()

    def setup_styles(self):
        """Configure modern dark theme palette and styles."""
        self.bg_dark = "#181825"
        self.bg_card = "#1e1e2e"
        self.fg_text = "#cdd6f4"
        self.accent_blue = "#89b4fa"
        self.accent_green = "#a6e3a1"
        self.accent_red = "#f38ba8"
        self.accent_yellow = "#f9e2af"

        self.root.configure(bg=self.bg_dark)
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Configure global ttk elements
        self.style.configure(".", background=self.bg_card, foreground=self.fg_text, font=("DejaVu Sans", 10))
        self.style.configure("TNotebook", background=self.bg_dark, tabmargins=[2, 5, 2, 0])
        self.style.configure("TNotebook.Tab", background=self.bg_card, foreground=self.fg_text, padding=[12, 6], font=("DejaVu Sans", 10, "bold"))
        self.style.map("TNotebook.Tab",
            background=[("selected", self.accent_blue), ("active", "#313244")],
            foreground=[("selected", "#11111b"), ("active", "#ffffff")]
        )

        self.style.configure("TButton", background="#313244", foreground=self.fg_text, padding=6, relief="flat", font=("DejaVu Sans", 9, "bold"))
        self.style.map("TButton", background=[("active", self.accent_blue)], foreground=[("active", "#11111b")])

        self.style.configure("Accent.TButton", background=self.accent_blue, foreground="#11111b", padding=6, font=("DejaVu Sans", 9, "bold"))
        self.style.map("Accent.TButton", background=[("active", "#b4befe")])

        self.style.configure("Danger.TButton", background=self.accent_red, foreground="#11111b", padding=6, font=("DejaVu Sans", 9, "bold"))
        self.style.map("Danger.TButton", background=[("active", "#eba0ac")])

        self.style.configure("Treeview", background="#11111b", foreground=self.fg_text, fieldbackground="#11111b", rowheight=24)
        self.style.configure("Treeview.Heading", background="#313244", foreground=self.accent_blue, font=("DejaVu Sans", 9, "bold"))

    def build_ui(self):
        # 1. Header Bar
        header = tk.Frame(self.root, bg="#11111b", height=50)
        header.pack(fill="x", side="top")

        title_lbl = tk.Label(
            header,
            text="🛡️ SCAPY NETWORK TOOLKIT & SUITE",
            font=("DejaVu Sans", 14, "bold"),
            fg=self.accent_blue,
            bg="#11111b"
        )
        title_lbl.pack(side="left", padx=15, pady=10)

        self.privilege_lbl = tk.Label(header, text="Checking Privileges...", font=("DejaVu Sans", 9, "bold"), bg="#11111b")
        self.privilege_lbl.pack(side="right", padx=15)

        # 2. Main Tabbed Interface (Notebook)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Add 10 tabs
        self.tab_sniff = ttk.Frame(self.notebook)
        self.tab_pcap = ttk.Frame(self.notebook)
        self.tab_arp = ttk.Frame(self.notebook)
        self.tab_port = ttk.Frame(self.notebook)
        self.tab_crafter = ttk.Frame(self.notebook)
        self.tab_wifi = ttk.Frame(self.notebook)
        self.tab_gateway = ttk.Frame(self.notebook)
        self.tab_beacon = ttk.Frame(self.notebook)
        self.tab_http = ttk.Frame(self.notebook)
        self.tab_ssh = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_sniff, text="📡 Sniffer")
        self.notebook.add(self.tab_pcap, text="📁 PCAP")
        self.notebook.add(self.tab_arp, text="🔍 ARP")
        self.notebook.add(self.tab_port, text="🎯 Ports/Ping")
        self.notebook.add(self.tab_crafter, text="🛠️ Crafter")
        self.notebook.add(self.tab_wifi, text="📶 Wi-Fi")
        self.notebook.add(self.tab_gateway, text="🌐 Gateway")
        self.notebook.add(self.tab_beacon, text="🛡️ Beacons")
        self.notebook.add(self.tab_http, text="🌍 Requests")
        self.notebook.add(self.tab_ssh, text="🔐 SSH/SFTP")

        # Build tabs content
        self.build_tab_sniff()
        self.build_tab_pcap()
        self.build_tab_arp()
        self.build_tab_port()
        self.build_tab_crafter()
        self.build_tab_wifi()
        self.build_tab_gateway()
        self.build_tab_beacon()
        self.build_tab_http()
        self.build_tab_ssh()

        # 3. Bottom Log Console
        log_frame = tk.LabelFrame(self.root, text=" 📝 Real-Time System Log & Output ", bg=self.bg_card, fg=self.accent_blue, font=("DejaVu Sans", 9, "bold"))
        log_frame.pack(fill="x", side="bottom", padx=10, pady=(0, 5))

        self.log_box = ScrolledText(log_frame, height=7, bg="#11111b", fg=self.fg_text, font=("DejaVu Sans Mono", 9), insertbackground="white")
        self.log_box.pack(fill="x", padx=5, pady=5)

        btn_row = tk.Frame(log_frame, bg=self.bg_card)
        btn_row.pack(fill="x", padx=5, pady=(0, 4))
        ttk.Button(btn_row, text="Clear Logs", command=lambda: self.log_box.delete("1.0", tk.END)).pack(side="right")

    def check_root_status(self):
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if is_root:
            self.privilege_lbl.config(text="● ROOT: PERMITTED (Superuser)", fg=self.accent_green)
            self.log("[+] Running with ROOT privileges. Raw sockets and packet sniffing enabled.")
        else:
            self.privilege_lbl.config(text="▲ USER MODE (Run with sudo for sniffing)", fg=self.accent_yellow)
            self.log("[!] Warning: Running as normal user. Packet sniffing and raw socket crafting may require: sudo ./venv/bin/python gui.py")

    def log(self, text: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.insert(tk.END, f"[{timestamp}] {text}\n")
        self.log_box.see(tk.END)

    # ---------------------------------------------------------
    # TAB 1: Live Packet Sniffer
    # ---------------------------------------------------------
    def build_tab_sniff(self):
        ctrl = tk.Frame(self.tab_sniff, bg=self.bg_card)
        ctrl.pack(fill="x", padx=10, pady=10)

        tk.Label(ctrl, text="BPF Filter:", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.sniff_filter = ttk.Combobox(ctrl, values=["", "tcp", "udp", "icmp", "port 80 or port 443", "arp"], width=25)
        self.sniff_filter.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(ctrl, text="Max Count (0=∞):", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.sniff_count = ttk.Entry(ctrl, width=8)
        self.sniff_count.insert(0, "0")
        self.sniff_count.grid(row=0, column=3, padx=5, pady=5)

        self.sniff_save_pcap = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl, text="Save to PCAP", variable=self.sniff_save_pcap).grid(row=0, column=4, padx=10, pady=5)

        self.btn_start_sniff = ttk.Button(ctrl, text="▶ Start Sniffing", style="Accent.TButton", command=self.toggle_sniffing)
        self.btn_start_sniff.grid(row=0, column=5, padx=10, pady=5)

        # Table for live packets
        columns = ("#", "Source", "Destination", "Protocol", "Info")
        self.sniff_tree = ttk.Treeview(self.tab_sniff, columns=columns, show="headings", height=14)
        for col in columns:
            self.sniff_tree.heading(col, text=col)
        self.sniff_tree.column("#", width=50, anchor="center")
        self.sniff_tree.column("Source", width=140)
        self.sniff_tree.column("Destination", width=140)
        self.sniff_tree.column("Protocol", width=80, anchor="center")
        self.sniff_tree.column("Info", width=400)
        self.sniff_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.sniff_tree.bind("<Double-1>", self.on_packet_select)

    def toggle_sniffing(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.btn_start_sniff.config(text="⏹ Stop Sniffing", style="Danger.TButton")
            self.captured_packets.clear()
            for item in self.sniff_tree.get_children():
                self.sniff_tree.delete(item)

            filter_val = self.sniff_filter.get().strip()
            count_val = int(self.sniff_count.get().strip() or 0)
            save_val = self.sniff_save_pcap.get()

            self.log(f"[*] Starting live sniffer (Filter='{filter_val or 'All'}')...")
            self.sniffer_thread = threading.Thread(
                target=self._sniff_worker, args=(filter_val, count_val, save_val), daemon=True
            )
            self.sniffer_thread.start()
        else:
            self.is_sniffing = False
            self.btn_start_sniff.config(text="▶ Start Sniffing", style="Accent.TButton")
            self.log("[*] Stopping live sniffer...")

    def _sniff_worker(self, filter_expr, max_count, save_pcap):
        def handler(pkt):
            if not self.is_sniffing:
                return True  # Stop
            idx = len(self.captured_packets)
            self.captured_packets.append(pkt)

            src = pkt[IP].src if IP in pkt else (pkt.src if hasattr(pkt, "src") else "-")
            dst = pkt[IP].dst if IP in pkt else (pkt.dst if hasattr(pkt, "dst") else "-")
            proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else ("ICMP" if ICMP in pkt else pkt.summary().split()[0]))
            info = pkt.summary()

            self.root.after(0, lambda: self.sniff_tree.insert("", tk.END, values=(idx, src, dst, proto, info)))
            if max_count > 0 and len(self.captured_packets) >= max_count:
                self.root.after(0, self.toggle_sniffing)
                return True

        try:
            kwargs = {"prn": handler, "store": True}
            if filter_expr:
                kwargs["filter"] = filter_expr
            sniff(**kwargs)
        except Exception as e:
            self.root.after(0, lambda: self.log(f"[-] Sniffer error: {e}"))
            self.root.after(0, self.toggle_sniffing)

        if save_pcap and self.captured_packets:
            os.makedirs("captures", exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = f"captures/sniff_{ts}.pcap"
            wrpcap(pcap_file, self.captured_packets)
            self.root.after(0, lambda: self.log(f"[+] Saved {len(self.captured_packets)} packets to {pcap_file}"))

    def on_packet_select(self, event):
        item = self.sniff_tree.focus()
        if not item:
            return
        vals = self.sniff_tree.item(item, "values")
        idx = int(vals[0])
        if idx < len(self.captured_packets):
            pkt = self.captured_packets[idx]
            self.show_packet_popup(pkt, idx)

    def show_packet_popup(self, pkt, idx):
        win = tk.Toplevel(self.root)
        win.title(f"Packet #{idx} Deep Inspection (.show())")
        win.geometry("700x500")
        win.configure(bg=self.bg_dark)

        txt = ScrolledText(win, bg="#11111b", fg="#a6e3a1", font=("DejaVu Sans Mono", 9))
        txt.pack(fill="both", expand=True, padx=10, pady=10)

        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            pkt.show()
        txt.insert("1.0", f.getvalue())

    # ---------------------------------------------------------
    # TAB 2: PCAP Analyzer
    # ---------------------------------------------------------
    def build_tab_pcap(self):
        ctrl = tk.Frame(self.tab_pcap, bg=self.bg_card)
        ctrl.pack(fill="x", padx=10, pady=10)

        tk.Label(ctrl, text="PCAP File:", bg=self.bg_card, fg=self.fg_text).pack(side="left", padx=5)
        self.pcap_path_var = tk.StringVar(value="captures/sample_test.pcap")
        ttk.Entry(ctrl, textvariable=self.pcap_path_var, width=45).pack(side="left", padx=5)
        ttk.Button(ctrl, text="Browse...", command=self.browse_pcap).pack(side="left", padx=5)
        ttk.Button(ctrl, text="📂 Analyze PCAP", style="Accent.TButton", command=self.load_and_analyze_pcap).pack(side="left", padx=10)

        self.pcap_stats_lbl = tk.Label(self.tab_pcap, text="Select a PCAP file to view statistics and packets.", bg=self.bg_card, fg=self.accent_blue, font=("DejaVu Sans", 10, "bold"))
        self.pcap_stats_lbl.pack(fill="x", padx=10, pady=5)

        cols = ("#", "Summary")
        self.pcap_tree = ttk.Treeview(self.tab_pcap, columns=cols, show="headings", height=12)
        self.pcap_tree.heading("#", text="#")
        self.pcap_tree.heading("Summary", text="Packet Summary")
        self.pcap_tree.column("#", width=60, anchor="center")
        self.pcap_tree.column("Summary", width=750)
        self.pcap_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.pcap_tree.bind("<Double-1>", self.on_pcap_select)

    def browse_pcap(self):
        f = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if f:
            self.pcap_path_var.set(f)

    def load_and_analyze_pcap(self):
        path = self.pcap_path_var.get().strip()
        if not os.path.exists(path):
            messagebox.showerror("File Error", f"File '{path}' does not exist.")
            return

        for i in self.pcap_tree.get_children():
            self.pcap_tree.delete(i)

        self.log(f"[*] Reading PCAP file: {path} ...")
        pkts = load_pcap(path)
        if pkts is None:
            return

        self.loaded_pcap_packets = pkts
        self.pcap_stats_lbl.config(text=f"Total Packets: {len(pkts)} | File: {os.path.basename(path)}")
        for idx, p in enumerate(pkts):
            self.pcap_tree.insert("", tk.END, values=(idx, p.summary()))
        self.log(f"[+] Loaded {len(pkts)} packets from {path}.")

    def on_pcap_select(self, event):
        item = self.pcap_tree.focus()
        if not item or not hasattr(self, "loaded_pcap_packets"):
            return
        vals = self.pcap_tree.item(item, "values")
        idx = int(vals[0])
        self.show_packet_popup(self.loaded_pcap_packets[idx], idx)

    # ---------------------------------------------------------
    # TAB 3: ARP Network Discovery
    # ---------------------------------------------------------
    def build_tab_arp(self):
        ctrl = tk.Frame(self.tab_arp, bg=self.bg_card)
        ctrl.pack(fill="x", padx=10, pady=10)

        tk.Label(ctrl, text="IP Range / Subnet:", bg=self.bg_card, fg=self.fg_text).pack(side="left", padx=5)
        self.arp_range_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(ctrl, textvariable=self.arp_range_var, width=25).pack(side="left", padx=5)

        ttk.Button(ctrl, text="🔍 Scan LAN via ARP", style="Accent.TButton", command=self.run_arp_scan).pack(side="left", padx=10)

        cols = ("IP Address", "MAC Address")
        self.arp_tree = ttk.Treeview(self.tab_arp, columns=cols, show="headings", height=14)
        self.arp_tree.heading("IP Address", text="IP Address")
        self.arp_tree.heading("MAC Address", text="MAC Address")
        self.arp_tree.column("IP Address", width=250, anchor="center")
        self.arp_tree.column("MAC Address", width=350, anchor="center")
        self.arp_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def run_arp_scan(self):
        ip_range = self.arp_range_var.get().strip()
        for i in self.arp_tree.get_children():
            self.arp_tree.delete(i)

        self.log(f"[*] Sending ARP broadcast requests to {ip_range} ...")

        def worker():
            devs = scan_network(ip_range, timeout=2)
            self.root.after(0, lambda: self._fill_arp_results(devs))

        threading.Thread(target=worker, daemon=True).start()

    def _fill_arp_results(self, devs):
        for d in devs:
            self.arp_tree.insert("", tk.END, values=(d["ip"], d["mac"]))
        self.log(f"[+] ARP Scan completed. Found {len(devs)} active device(s).")

    # ---------------------------------------------------------
    # TAB 4: Host Ping & Port Scanner
    # ---------------------------------------------------------
    def build_tab_port(self):
        ctrl = tk.Frame(self.tab_port, bg=self.bg_card)
        ctrl.pack(fill="x", padx=10, pady=10)

        tk.Label(ctrl, text="Target IP:", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=0, padx=5, pady=5)
        self.port_target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(ctrl, textvariable=self.port_target_var, width=20).grid(row=0, column=1, padx=5, pady=5)

        tk.Label(ctrl, text="Ports (comma separated):", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=2, padx=5, pady=5)
        self.port_list_var = tk.StringVar(value="21, 22, 53, 80, 443, 8080")
        ttk.Entry(ctrl, textvariable=self.port_list_var, width=30).grid(row=0, column=3, padx=5, pady=5)

        ttk.Button(ctrl, text="Ping (ICMP)", command=self.run_ping).grid(row=0, column=4, padx=5, pady=5)
        ttk.Button(ctrl, text="🎯 TCP SYN Scan", style="Accent.TButton", command=self.run_port_scan).grid(row=0, column=5, padx=5, pady=5)

        cols = ("Port", "Status", "Protocol")
        self.port_tree = ttk.Treeview(self.tab_port, columns=cols, show="headings", height=12)
        for c in cols:
            self.port_tree.heading(c, text=c)
        self.port_tree.column("Port", width=120, anchor="center")
        self.port_tree.column("Status", width=180, anchor="center")
        self.port_tree.column("Protocol", width=120, anchor="center")
        self.port_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def run_ping(self):
        target = self.port_target_var.get().strip()
        self.log(f"[*] Sending ICMP ping to {target} ...")

        def worker():
            is_up, _ = icmp_ping(target, timeout=2)
            msg = f"[+] Host {target} is UP and responding to Ping!" if is_up else f"[-] Host {target} did not respond to Ping."
            self.root.after(0, lambda: self.log(msg))

        threading.Thread(target=worker, daemon=True).start()

    def run_port_scan(self):
        target = self.port_target_var.get().strip()
        ports_str = self.port_list_var.get().strip()
        try:
            ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
        except ValueError:
            ports = COMMON_PORTS

        for i in self.port_tree.get_children():
            self.port_tree.delete(i)

        self.log(f"[*] Starting TCP SYN Scan on {target} ({len(ports)} ports)...")

        def worker():
            for p in ports:
                st = tcp_syn_scan_port(target, p, timeout=1.0)
                self.root.after(0, lambda pt=p, s=st: self.port_tree.insert("", tk.END, values=(pt, s, "TCP")))
            self.root.after(0, lambda: self.log(f"[+] Scan completed for {target}."))

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------------------------------------------
    # TAB 5: Packet Crafter
    # ---------------------------------------------------------
    def build_tab_crafter(self):
        f = tk.Frame(self.tab_crafter, bg=self.bg_card)
        f.pack(fill="both", expand=True, padx=20, pady=15)

        tk.Label(f, text="Protocol:", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=0, sticky="w", pady=4)
        self.craft_proto = ttk.Combobox(f, values=["TCP", "UDP", "ICMP", "Ethernet"], width=15)
        self.craft_proto.set("TCP")
        self.craft_proto.grid(row=0, column=1, sticky="w", pady=4)

        tk.Label(f, text="Destination IP:", bg=self.bg_card, fg=self.fg_text).grid(row=1, column=0, sticky="w", pady=4)
        self.craft_dst = ttk.Entry(f, width=25)
        self.craft_dst.insert(0, "127.0.0.1")
        self.craft_dst.grid(row=1, column=1, sticky="w", pady=4)

        tk.Label(f, text="Source IP (Spoof):", bg=self.bg_card, fg=self.fg_text).grid(row=2, column=0, sticky="w", pady=4)
        self.craft_src = ttk.Entry(f, width=25)
        self.craft_src.grid(row=2, column=1, sticky="w", pady=4)

        tk.Label(f, text="Dest Port:", bg=self.bg_card, fg=self.fg_text).grid(row=3, column=0, sticky="w", pady=4)
        self.craft_dport = ttk.Entry(f, width=10)
        self.craft_dport.insert(0, "80")
        self.craft_dport.grid(row=3, column=1, sticky="w", pady=4)

        tk.Label(f, text="TCP Flags (S/A/F/R):", bg=self.bg_card, fg=self.fg_text).grid(row=4, column=0, sticky="w", pady=4)
        self.craft_flags = ttk.Entry(f, width=10)
        self.craft_flags.insert(0, "S")
        self.craft_flags.grid(row=4, column=1, sticky="w", pady=4)

        tk.Label(f, text="Payload (Data):", bg=self.bg_card, fg=self.fg_text).grid(row=5, column=0, sticky="w", pady=4)
        self.craft_payload = ttk.Entry(f, width=40)
        self.craft_payload.grid(row=5, column=1, sticky="w", pady=4)

        btn_box = tk.Frame(f, bg=self.bg_card)
        btn_box.grid(row=6, column=0, columnspan=2, pady=15)
        ttk.Button(btn_box, text="Preview (.show())", command=self.preview_crafted_packet).pack(side="left", padx=5)
        ttk.Button(btn_box, text="🚀 Transmit Packet (send)", style="Accent.TButton", command=self.send_crafted_packet).pack(side="left", padx=5)

    def _build_crafted_packet(self):
        proto = self.craft_proto.get()
        dst = self.craft_dst.get().strip() or "127.0.0.1"
        src = self.craft_src.get().strip() or None
        dport = int(self.craft_dport.get().strip() or 80)
        flags = self.craft_flags.get().strip() or "S"
        payload = self.craft_payload.get()

        if proto == "TCP":
            return craft_ip_tcp_packet(dst_ip=dst, dport=dport, src_ip=src, flags=flags, payload=payload)
        elif proto == "UDP":
            return craft_ip_udp_packet(dst_ip=dst, dport=dport, src_ip=src, payload=payload)
        elif proto == "ICMP":
            return craft_icmp_packet(dst_ip=dst, src_ip=src)
        else:
            inner = craft_ip_tcp_packet(dst_ip=dst, dport=dport, src_ip=src, flags=flags)
            return craft_ethernet_packet(inner_packet=inner)

    def preview_crafted_packet(self):
        pkt = self._build_crafted_packet()
        self.show_packet_popup(pkt, 0)

    def send_crafted_packet(self):
        pkt = self._build_crafted_packet()
        is_l2 = self.craft_proto.get() == "Ethernet"
        self.log(f"[*] Sending crafted {self.craft_proto.get()} packet to {self.craft_dst.get()} ...")
        threading.Thread(target=lambda: preview_and_send(pkt, use_layer2=is_l2, count=1), daemon=True).start()

    # ---------------------------------------------------------
    # TAB 6: Wi-Fi Manager
    # ---------------------------------------------------------
    def build_tab_wifi(self):
        ctrl = tk.Frame(self.tab_wifi, bg=self.bg_card)
        ctrl.pack(fill="x", padx=10, pady=10)

        ttk.Button(ctrl, text="📶 Scan Nearby Wi-Fi", style="Accent.TButton", command=self.run_wifi_scan).pack(side="left", padx=5)
        ttk.Button(ctrl, text="🔑 Show Saved Passwords", command=self.run_wifi_passwords).pack(side="left", padx=5)

        cols = ("SSID", "Signal", "Security", "Channel", "Status")
        self.wifi_tree = ttk.Treeview(self.tab_wifi, columns=cols, show="headings", height=10)
        for c in cols:
            self.wifi_tree.heading(c, text=c)
        self.wifi_tree.column("SSID", width=220)
        self.wifi_tree.column("Signal", width=100, anchor="center")
        self.wifi_tree.column("Security", width=180, anchor="center")
        self.wifi_tree.column("Channel", width=80, anchor="center")
        self.wifi_tree.column("Status", width=120, anchor="center")
        self.wifi_tree.pack(fill="both", expand=True, padx=10, pady=5)

        # Connection box
        conn_f = tk.LabelFrame(self.tab_wifi, text=" Connect to Wi-Fi ", bg=self.bg_card, fg=self.accent_blue)
        conn_f.pack(fill="x", padx=10, pady=5)
        tk.Label(conn_f, text="SSID:", bg=self.bg_card, fg=self.fg_text).pack(side="left", padx=5)
        self.wifi_conn_ssid = ttk.Entry(conn_f, width=20)
        self.wifi_conn_ssid.pack(side="left", padx=5)
        tk.Label(conn_f, text="Password:", bg=self.bg_card, fg=self.fg_text).pack(side="left", padx=5)
        self.wifi_conn_pwd = ttk.Entry(conn_f, width=20, show="*")
        self.wifi_conn_pwd.pack(side="left", padx=5)
        ttk.Button(conn_f, text="Connect", style="Accent.TButton", command=self.do_wifi_connect).pack(side="left", padx=10)

    def run_wifi_scan(self):
        for i in self.wifi_tree.get_children():
            self.wifi_tree.delete(i)
        self.log("[*] Scanning nearby Wi-Fi networks...")

        def worker():
            nets = scan_nearby_wifi()
            self.root.after(0, lambda: self._fill_wifi_results(nets))

        threading.Thread(target=worker, daemon=True).start()

    def _fill_wifi_results(self, nets):
        for n in nets:
            st = "Connected (*)" if n["connected"] else ""
            self.wifi_tree.insert("", tk.END, values=(n["ssid"], f"{n['signal']}%", n["security"], n["channel"], st))
        self.log(f"[+] Found {len(nets)} Wi-Fi networks.")

    def run_wifi_passwords(self):
        self.log("[*] Retrieving saved Wi-Fi connection passwords...")
        saved = get_saved_wifi_passwords()
        win = tk.Toplevel(self.root)
        win.title("Saved Wi-Fi Passwords")
        win.geometry("600x400")
        win.configure(bg=self.bg_dark)

        cols = ("Profile / SSID", "Stored Password")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("Profile / SSID", text="Profile / SSID")
        tree.heading("Stored Password", text="Stored Password")
        tree.column("Profile / SSID", width=250)
        tree.column("Stored Password", width=300)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        for s in saved:
            tree.insert("", tk.END, values=(s["name"], s["password"]))

    def do_wifi_connect(self):
        ssid = self.wifi_conn_ssid.get().strip()
        pwd = self.wifi_conn_pwd.get().strip()
        if not ssid:
            messagebox.showwarning("Missing SSID", "Please enter an SSID to connect.")
            return

        self.log(f"[*] Attempting connection to '{ssid}' ...")
        threading.Thread(target=lambda: connect_to_wifi(ssid, pwd), daemon=True).start()

    # ---------------------------------------------------------
    # TAB 7: Router Gateway Scanner
    # ---------------------------------------------------------
    def build_tab_gateway(self):
        top = tk.Frame(self.tab_gateway, bg=self.bg_card)
        top.pack(fill="x", padx=10, pady=10)

        self.gw_info_lbl = tk.Label(top, text="Default Gateway: Not detected", bg=self.bg_card, fg=self.accent_blue, font=("DejaVu Sans", 10, "bold"))
        self.gw_info_lbl.pack(side="left", padx=5)

        ttk.Button(top, text="🌐 Auto-Detect & Scan Router", style="Accent.TButton", command=self.run_gateway_audit).pack(side="right", padx=10)

        cols = ("Port", "Status", "Service", "Description / Security Notes")
        self.gw_tree = ttk.Treeview(self.tab_gateway, columns=cols, show="headings", height=12)
        for c in cols:
            self.gw_tree.heading(c, text=c)
        self.gw_tree.column("Port", width=80, anchor="center")
        self.gw_tree.column("Status", width=100, anchor="center")
        self.gw_tree.column("Service", width=120, anchor="center")
        self.gw_tree.column("Description / Security Notes", width=450)
        self.gw_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def run_gateway_audit(self):
        for i in self.gw_tree.get_children():
            self.gw_tree.delete(i)
        self.log("[*] Detecting default gateway and auditing router services...")

        def worker():
            info = get_default_gateway()
            if not info:
                self.root.after(0, lambda: self.log("[-] Default gateway could not be resolved."))
                return
            gw_ip = info["gateway_ip"]
            self.root.after(0, lambda: self.gw_info_lbl.config(text=f"Router Gateway: {gw_ip} | Interface: {info['interface']}"))

            results = scan_router_ports(gw_ip)
            for port, status, sname, desc in results:
                self.root.after(0, lambda p=port, s=status, sn=sname, d=desc: self.gw_tree.insert("", tk.END, values=(p, s, sn, d)))
            self.root.after(0, lambda: self.log(f"[+] Router audit completed for {gw_ip}."))

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------------------------------------------
    # TAB 8: Wi-Fi Beacon Inspector
    # ---------------------------------------------------------
    def build_tab_beacon(self):
        ctrl = tk.Frame(self.tab_beacon, bg=self.bg_card)
        ctrl.pack(fill="x", padx=10, pady=10)

        ttk.Button(ctrl, text="📁 Analyze Wireless PCAP", style="Accent.TButton", command=self.run_beacon_pcap).pack(side="left", padx=5)

        cols = ("BSSID", "Channel", "Security Rating", "SSID")
        self.beacon_tree = ttk.Treeview(self.tab_beacon, columns=cols, show="headings", height=14)
        for c in cols:
            self.beacon_tree.heading(c, text=c)
        self.beacon_tree.column("BSSID", width=160, anchor="center")
        self.beacon_tree.column("Channel", width=80, anchor="center")
        self.beacon_tree.column("Security Rating", width=250)
        self.beacon_tree.column("SSID", width=250)
        self.beacon_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def run_beacon_pcap(self):
        f = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if not f:
            return
        for i in self.beacon_tree.get_children():
            self.beacon_tree.delete(i)
        self.log(f"[*] Analyzing wireless beacons in {f} ...")

        def worker():
            aps = analyze_wireless_pcap(f)
            for ap in aps:
                self.root.after(0, lambda a=ap: self.beacon_tree.insert("", tk.END, values=(a["bssid"], a["channel"], a["security"], a["ssid"])))
            self.root.after(0, lambda: self.log(f"[+] Found {len(aps)} Access Points in PCAP."))

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------------------------------------------
    # TAB 9: HTTP Reconnaissance (Requests)
    # ---------------------------------------------------------
    def build_tab_http(self):
        ctrl = tk.Frame(self.tab_http, bg=self.bg_card)
        ctrl.pack(fill="x", padx=10, pady=10)

        tk.Label(ctrl, text="Target URL / Domain / IP:", bg=self.bg_card, fg=self.fg_text).pack(side="left", padx=5)
        self.http_target_var = tk.StringVar(value="github.com")
        ttk.Entry(ctrl, textvariable=self.http_target_var, width=30).pack(side="left", padx=5)

        ttk.Button(ctrl, text="Check Status & Banner", style="Accent.TButton", command=self.run_http_check).pack(side="left", padx=5)
        ttk.Button(ctrl, text="Audit Security Headers", command=self.run_http_headers).pack(side="left", padx=5)
        ttk.Button(ctrl, text="🌍 IP / Geo Threat Intel", command=self.run_http_geo).pack(side="left", padx=5)

        self.http_display = ScrolledText(self.tab_http, bg="#11111b", fg="#a6e3a1", font=("DejaVu Sans Mono", 9), height=14)
        self.http_display.pack(fill="both", expand=True, padx=10, pady=10)

    def run_http_check(self):
        target = self.http_target_var.get().strip()
        self.http_display.delete("1.0", tk.END)
        self.log(f"[*] Sending HTTP GET to {target} ...")

        def worker():
            resp = check_website(target)
            if resp:
                txt = f"URL: {resp.url}\nStatus: {resp.status_code}\nServer: {resp.headers.get('Server')}\nContent Length: {len(resp.content)} bytes\n\nHeaders:\n"
                for k, v in resp.headers.items():
                    txt += f"  {k}: {v}\n"
                self.root.after(0, lambda: self.http_display.insert("1.0", txt))

        threading.Thread(target=worker, daemon=True).start()

    def run_http_headers(self):
        target = self.http_target_var.get().strip()
        self.http_display.delete("1.0", tk.END)

        def worker():
            resp = check_website(target)
            if resp:
                import io
                from contextlib import redirect_stdout
                f = io.StringIO()
                with redirect_stdout(f):
                    audit_security_headers(resp)
                self.root.after(0, lambda: self.http_display.insert("1.0", f.getvalue()))

        threading.Thread(target=worker, daemon=True).start()

    def run_http_geo(self):
        target = self.http_target_var.get().strip()
        self.http_display.delete("1.0", tk.END)

        def worker():
            data = ip_threat_and_geo_lookup(target)
            if data:
                txt = f"IP Geolocation for: {target}\n" + "-" * 40 + "\n"
                for k, v in data.items():
                    txt += f"  {k:<15}: {v}\n"
                self.root.after(0, lambda: self.http_display.insert("1.0", txt))

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------------------------------------------
    # TAB 10: Remote SSH & SFTP (Paramiko)
    # ---------------------------------------------------------
    def build_tab_ssh(self):
        top = tk.Frame(self.tab_ssh, bg=self.bg_card)
        top.pack(fill="x", padx=10, pady=10)

        tk.Label(top, text="Host:", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=0, padx=4, pady=4)
        self.ssh_host = ttk.Entry(top, width=16)
        self.ssh_host.insert(0, "127.0.0.1")
        self.ssh_host.grid(row=0, column=1, padx=4, pady=4)

        tk.Label(top, text="Port:", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=2, padx=4, pady=4)
        self.ssh_port = ttk.Entry(top, width=6)
        self.ssh_port.insert(0, "22")
        self.ssh_port.grid(row=0, column=3, padx=4, pady=4)

        tk.Label(top, text="User:", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=4, padx=4, pady=4)
        self.ssh_user = ttk.Entry(top, width=12)
        self.ssh_user.insert(0, "root")
        self.ssh_user.grid(row=0, column=5, padx=4, pady=4)

        tk.Label(top, text="Password:", bg=self.bg_card, fg=self.fg_text).grid(row=0, column=6, padx=4, pady=4)
        self.ssh_pwd = ttk.Entry(top, width=14, show="*")
        self.ssh_pwd.grid(row=0, column=7, padx=4, pady=4)

        self.btn_ssh_conn = ttk.Button(top, text="Connect", style="Accent.TButton", command=self.do_ssh_connect)
        self.btn_ssh_conn.grid(row=0, column=8, padx=8, pady=4)

        # Exec row
        exec_f = tk.Frame(self.tab_ssh, bg=self.bg_card)
        exec_f.pack(fill="x", padx=10, pady=5)
        tk.Label(exec_f, text="Command:", bg=self.bg_card, fg=self.fg_text).pack(side="left", padx=5)
        self.ssh_cmd = ttk.Entry(exec_f, width=45)
        self.ssh_cmd.insert(0, "uname -a && uptime")
        self.ssh_cmd.pack(side="left", padx=5)
        ttk.Button(exec_f, text="Exec Command", style="Accent.TButton", command=self.do_ssh_exec).pack(side="left", padx=5)
        ttk.Button(exec_f, text="🛡️ System Audit", command=self.do_ssh_audit).pack(side="left", padx=5)

        self.ssh_terminal = ScrolledText(self.tab_ssh, bg="#11111b", fg="#cdd6f4", font=("DejaVu Sans Mono", 9), height=10)
        self.ssh_terminal.pack(fill="both", expand=True, padx=10, pady=5)

    def do_ssh_connect(self):
        if self.ssh_client and self.ssh_client.is_connected:
            self.ssh_client.close()
            self.btn_ssh_conn.config(text="Connect", style="Accent.TButton")
            self.log("[*] SSH Session disconnected.")
            return

        host = self.ssh_host.get().strip()
        port = int(self.ssh_port.get().strip() or 22)
        user = self.ssh_user.get().strip()
        pwd = self.ssh_pwd.get()

        self.log(f"[*] Connecting to {user}@{host}:{port} via Paramiko SSH ...")

        def worker():
            try:
                self.ssh_client = RemoteSSHClient()
                ok = self.ssh_client.connect(hostname=host, port=port, username=user, password=pwd)
                if ok:
                    self.root.after(0, lambda: self.btn_ssh_conn.config(text="Disconnect", style="Danger.TButton"))
                    self.root.after(0, lambda: self.log(f"[+] Connected to {user}@{host}!"))
            except Exception as e:
                self.root.after(0, lambda: self.log(f"[-] SSH connection failed: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def do_ssh_exec(self):
        if not self.ssh_client or not self.ssh_client.is_connected:
            messagebox.showwarning("SSH Not Connected", "Please connect to an SSH server first.")
            return

        cmd = self.ssh_cmd.get().strip()
        self.log(f"[*] Executing remote SSH: {cmd} ...")

        def worker():
            code, out, err = self.ssh_client.exec_command(cmd)
            res = f"$ {cmd}\n(exit code: {code})\n" + (out if out else "") + ("\nSTDERR: " + err if err else "") + "\n\n"
            self.root.after(0, lambda: self.ssh_terminal.insert(tk.END, res))
            self.root.after(0, lambda: self.ssh_terminal.see(tk.END))

        threading.Thread(target=worker, daemon=True).start()

    def do_ssh_audit(self):
        if not self.ssh_client or not self.ssh_client.is_connected:
            messagebox.showwarning("SSH Not Connected", "Please connect to an SSH server first.")
            return
        self.log("[*] Running remote security & health audit ...")
        threading.Thread(target=self.ssh_client.run_system_audit, daemon=True).start()


def main():
    root = tk.Tk()
    app = ScapyToolkitGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
