#!/usr/bin/env python3
"""
PCAP File Analyzer Module
Uses Scapy's rdpcap() and .show() to inspect and dissect pre-captured packet files.
"""

import os
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP


def load_pcap(filepath: str):
    """
    Reads a .pcap file using rdpcap().
    Returns a Scapy PacketList or None on error.
    """
    if not os.path.exists(filepath):
        print(f"[-] Error: File '{filepath}' not found.")
        return None

    print(f"[*] Reading PCAP file: {filepath} ...")
    try:
        packets = rdpcap(filepath)
        print(f"[+] Loaded {len(packets)} packets successfully.")
        return packets
    except Exception as e:
        print(f"[-] Failed to read PCAP: {e}")
        return None


def print_pcap_statistics(packets):
    """
    Calculates and displays overview statistics for the packet capture.
    """
    if not packets:
        print("[-] No packets to analyze.")
        return

    proto_counter = Counter()
    ip_counter = Counter()

    for pkt in packets:
        if IP in pkt:
            ip_counter[pkt[IP].src] += 1
            ip_counter[pkt[IP].dst] += 1
            if TCP in pkt:
                proto_counter["TCP"] += 1
            elif UDP in pkt:
                proto_counter["UDP"] += 1
            elif ICMP in pkt:
                proto_counter["ICMP"] += 1
            else:
                proto_counter[f"IP (proto={pkt[IP].proto})"] += 1
        elif ARP in pkt:
            proto_counter["ARP"] += 1
        else:
            proto_counter["Other"] += 1

    print("\n" + "=" * 50)
    print("           PCAP FILE OVERVIEW")
    print("=" * 50)
    print(f"Total Packets: {len(packets)}")
    print("\n[ Protocols Distribution ]")
    for proto, count in proto_counter.most_common():
        pct = (count / len(packets)) * 100
        print(f"  - {proto:<15}: {count:<6} ({pct:.1f}%)")

    print("\n[ Top Active IP Addresses ]")
    for ip_addr, count in ip_counter.most_common(5):
        print(f"  - {ip_addr:<15}: {count} appearances")
    print("=" * 50 + "\n")


def inspect_packet(packets, index: int):
    """
    Displays the deep structure of a specific packet using .show().
    """
    if index < 0 or index >= len(packets):
        print(f"[-] Invalid index. Please choose between 0 and {len(packets) - 1}.")
        return

    pkt = packets[index]
    print("\n" + "=" * 60)
    print(f"[*] Packet #{index} - Complete Layer Dissection (.show())")
    print("=" * 60)
    pkt.show()
    print("=" * 60 + "\n")


def list_packets_summary(packets, limit: int = 20):
    """
    Lists a brief summary of the first `limit` packets in the capture.
    """
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
