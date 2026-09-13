"""
Core Configuration & Constants for Scapy Network Toolkit.
"""

import os
from pathlib import Path

# Project Directories
BASE_DIR = Path(__file__).resolve().parent.parent
CAPTURES_DIR = BASE_DIR / "captures"
CAPTURES_DIR.mkdir(exist_ok=True)

# Default Scanning & Network Settings
DEFAULT_TIMEOUT = 2.0
DEFAULT_PING_TIMEOUT = 1.5
DEFAULT_SYN_TIMEOUT = 1.0
DEFAULT_INTERFACE = None

# Common Port Dictionaries
COMMON_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote)",
    25: "SMTP (Mail Sending)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Server)",
    110: "POP3 (Mail Retrieval)",
    143: "IMAP (Mail Access)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB / Samba (File Sharing)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    8080: "HTTP Proxy / Alternate Web",
    8443: "HTTPS Alternate Web",
}

ROUTER_COMMON_SERVICES = {
    80: "HTTP (Router Web Admin UI)",
    443: "HTTPS (Router SSL Admin UI)",
    22: "SSH (Secure CLI Management)",
    23: "Telnet (Insecure CLI - High Risk!)",
    53: "DNS (Local DNS Resolver/Relay)",
    67: "DHCP Server",
    139: "NetBIOS (LAN Sharing)",
    445: "SMB (Router USB/Storage Sharing)",
    1900: "UPnP (Universal Plug and Play - Auto Port Mapping)",
    5000: "UPnP Alternate / Media Server",
    7547: "CWMP / TR-069 (ISP Remote Management Port - Vulnerability Target)",
    8080: "HTTP Alternate (Router Secondary Web UI)",
}

# Terminal Palette
COLORS = {
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "PURPLE": "\033[95m",
    "BLUE": "\033[94m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}
