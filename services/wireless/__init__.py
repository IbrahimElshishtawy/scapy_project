"""
Wireless & 802.11 Wi-Fi services.
"""

from .wifi_manager import (
    scan_nearby_wifi,
    get_saved_wifi_passwords,
    connect_to_wifi,
)
from .beacon_analyzer import (
    analyze_beacon_packet,
    analyze_wireless_pcap,
)
from .password_auditor import (
    calculate_entropy,
    audit_password_strength,
)

__all__ = [
    "scan_nearby_wifi",
    "get_saved_wifi_passwords",
    "connect_to_wifi",
    "analyze_beacon_packet",
    "analyze_wireless_pcap",
    "calculate_entropy",
    "audit_password_strength",
]
