"""
Services Layer for Scapy Network Toolkit.
Exposes clean, decoupled domain services for network, wireless, web, and remote operations.
"""

from .packet import (
    format_packet_summary,
    extract_packet_meta,
    capture_packets,
    save_packets_to_pcap,
    load_pcap_file,
    calculate_pcap_statistics,
    dissect_packet_details,
    craft_tcp_packet,
    craft_udp_packet,
    craft_icmp_packet,
    craft_ethernet_packet,
    send_crafted_packet,
)
from .scanner import (
    scan_network,
    icmp_ping,
    tcp_syn_scan_port,
    scan_target_ports,
    get_default_gateway,
    scan_router_ports,
    evaluate_router_security,
)
from .wireless import (
    scan_nearby_wifi,
    get_saved_wifi_passwords,
    connect_to_wifi,
    analyze_beacon_packet,
    analyze_wireless_pcap,
    calculate_entropy,
    audit_password_strength,
)
from .web import (
    check_website,
    audit_security_headers,
    ip_threat_and_geo_lookup,
    send_post_request,
)
from .remote import (
    RemoteSSHClient,
)

__all__ = [
    # Packet
    "format_packet_summary",
    "extract_packet_meta",
    "capture_packets",
    "save_packets_to_pcap",
    "load_pcap_file",
    "calculate_pcap_statistics",
    "dissect_packet_details",
    "craft_tcp_packet",
    "craft_udp_packet",
    "craft_icmp_packet",
    "craft_ethernet_packet",
    "send_crafted_packet",
    # Scanner
    "scan_network",
    "icmp_ping",
    "tcp_syn_scan_port",
    "scan_target_ports",
    "get_default_gateway",
    "scan_router_ports",
    "evaluate_router_security",
    # Wireless
    "scan_nearby_wifi",
    "get_saved_wifi_passwords",
    "connect_to_wifi",
    "analyze_beacon_packet",
    "analyze_wireless_pcap",
    "calculate_entropy",
    "audit_password_strength",
    # Web
    "check_website",
    "audit_security_headers",
    "ip_threat_and_geo_lookup",
    "send_post_request",
    # Remote
    "RemoteSSHClient",
]
