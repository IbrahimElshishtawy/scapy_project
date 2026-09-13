"""
Main Application Window & Lifecycle Controller for Scapy Toolkit GUI.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk

from gui.theme import apply_theme
from gui.widgets.status_bar import HeaderStatusBar
from gui.widgets.log_console import LogConsoleWidget
from gui.tabs import (
    SnifferTab,
    PcapTab,
    ArpTab,
    PortTab,
    CrafterTab,
    WifiTab,
    GatewayTab,
    BeaconTab,
    HttpTab,
    SshTab,
)
from core.privileges import is_root


class ScapyToolkitApp:
    """Main GUI Application Controller."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🛡️ Scapy & Network Security Toolkit (Enterprise GUI)")
        self.root.geometry("1120x790")
        self.root.minsize(950, 650)

        # Apply dark styling
        apply_theme(self.root)

        # 1. Header Bar
        self.header = HeaderStatusBar(self.root)

        # 2. Tabs Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Initialize Tabs
        self.tab_sniff = SnifferTab(self.notebook, self)
        self.tab_pcap = PcapTab(self.notebook, self)
        self.tab_arp = ArpTab(self.notebook, self)
        self.tab_port = PortTab(self.notebook, self)
        self.tab_crafter = CrafterTab(self.notebook, self)
        self.tab_wifi = WifiTab(self.notebook, self)
        self.tab_gateway = GatewayTab(self.notebook, self)
        self.tab_beacon = BeaconTab(self.notebook, self)
        self.tab_http = HttpTab(self.notebook, self)
        self.tab_ssh = SshTab(self.notebook, self)

        # Add tabs
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

        # 3. Bottom Log Console
        self.console = LogConsoleWidget(self.root, height=7)

        self._check_startup()

    def _check_startup(self):
        if is_root():
            self.log("[+] Running with ROOT privileges. Raw sockets and packet sniffing enabled.")
        else:
            self.log("[!] Advisory: Running in standard user mode. Run with 'sudo ./venv/bin/python gui.py' for live raw sniffing.")

    def log(self, message: str):
        """Global log forwarder to console."""
        self.console.log(message)


def launch_gui():
    """Initializes and starts the Tkinter event loop."""
    root = tk.Tk()
    app = ScapyToolkitApp(root)
    root.mainloop()
