#!/usr/bin/env python3
"""
PCAP File Analyzer Module (Compatibility Shim).
Delegates to services.packet.pcap_service.
"""

import os
from services.packet.pcap_service import (
    load_pcap_file,
    calculate_pcap_statistics,
    dissect_packet_details
)


def load_pcap(filepath: str):
    """Reads a .pcap file using services.packet.pcap_service."""
    try:
        print(f"[*] Reading PCAP file: {filepath} ...")
        packets = load_pcap_file(filepath)
        print(f"[+] Loaded {len(packets)} packets successfully.")
        return packets
    except Exception as e:
        print(f"[-] Failed to read PCAP: {e}")
        return None


def print_pcap_statistics(packets):
    """Displays overview statistics for the packet capture."""
    if not packets:
        print("[-] No packets to analyze.")
        return

    stats = calculate_pcap_statistics(packets)
    total = stats["total_packets"]

    print("\n" + "=" * 50)
    print("           PCAP FILE OVERVIEW")
    print("=" * 50)
    print(f"Total Packets: {total}")
    print("\n[ Protocols Distribution ]")
    for proto, count in stats["protocol_counts"].items():
        pct = (count / total) * 100 if total > 0 else 0
        print(f"  - {proto:<15}: {count:<6} ({pct:.1f}%)")

    print("\n[ Top Active IP Addresses ]")
    for ip_addr, count in stats["top_ips"][:5]:
        print(f"  - {ip_addr:<15}: {count} appearances")
    print("=" * 50 + "\n")


def inspect_packet(packets, index: int):
    """Displays deep structure of packet using .show()."""
    if index < 0 or index >= len(packets):
        print(f"[-] Invalid index. Please choose between 0 and {len(packets) - 1}.")
        return

    pkt = packets[index]
    print("\n" + "=" * 60)
    print(f"[*] Packet #{index} - Complete Layer Dissection (.show())")
    print("=" * 60)
    print(dissect_packet_details(pkt))
    print("=" * 60 + "\n")


def list_packets_summary(packets, limit: int = 20):
    """Lists a brief summary of first packets."""
    print("\n" + "-" * 70)
    print(f"{'#':<5} | {'Summary'}")
    print("-" * 70)
    for i, pkt in enumerate(packets[:limit]):
        print(f"{i:<5} | {pkt.summary()}")
    if len(packets) > limit:
        print(f"... and {len(packets) - limit} more packets.")
    print("-" * 70 + "\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        pkts = load_pcap(sys.argv[1])
        if pkts:
            print_pcap_statistics(pkts)
            list_packets_summary(pkts)
            if len(pkts) > 0:
                inspect_packet(pkts, 0)
    else:
        print("Usage: python pcap_analyzer.py <path_to_pcap>")
