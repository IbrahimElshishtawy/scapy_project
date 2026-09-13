"""
PCAP Capture Reader & Deep Packet Dissection Service.
"""

import os
from collections import Counter
from typing import Dict, Any, List, Optional
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP


def load_pcap_file(filepath: str) -> List[Any]:
    """Reads and parses a .pcap / .pcapng file into Scapy packets."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")
    return rdpcap(filepath)


def calculate_pcap_statistics(packets: List[Any]) -> Dict[str, Any]:
    """Computes comprehensive protocol breakdown and talker statistics."""
    total = len(packets)
    proto_counts = Counter()
    ip_talkers = Counter()

    for p in packets:
        if p.haslayer(IP):
            ip_talkers[p[IP].src] += 1
            ip_talkers[p[IP].dst] += 1
            if p.haslayer(TCP):
                proto_counts["TCP"] += 1
            elif p.haslayer(UDP):
                proto_counts["UDP"] += 1
            elif p.haslayer(ICMP):
                proto_counts["ICMP"] += 1
            else:
                proto_counts[f"Other IP ({p[IP].proto})"] += 1
        elif p.haslayer(ARP):
            proto_counts["ARP"] += 1
        else:
            proto_counts["Non-IP / L2"] += 1

    return {
        "total_packets": total,
        "protocol_counts": dict(proto_counts),
        "top_ips": ip_talkers.most_common(10),
    }


def dissect_packet_details(packet) -> str:
    """Dissects packet and returns formatted text string using .show()."""
    return packet.show(dump=True)
