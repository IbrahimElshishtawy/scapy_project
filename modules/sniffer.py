#!/usr/bin/env python3
"""
Packet Sniffer & Capture Module
Uses Scapy's sniff(), .show(), and wrpcap() for real-time network traffic analysis.
"""

import os
from datetime import datetime
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP


def format_packet_summary(packet):
    """Returns a one-line colored summary of the packet."""
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "IP"
        info = ""

        if TCP in packet:
            proto = "TCP"
            flags = packet[TCP].sprintf('%TCP.flags%')
            info = f"{packet[TCP].sport} -> {packet[TCP].dport} [{flags}]"
        elif UDP in packet:
            proto = "UDP"
            info = f"{packet[UDP].sport} -> {packet[UDP].dport} (len={packet[UDP].len})"
        elif ICMP in packet:
            proto = "ICMP"
            info = f"type={packet[ICMP].type} code={packet[ICMP].code}"
        else:
            proto = f"Proto({packet[IP].proto})"

        return f"{src:<15} -> {dst:<15} | {proto:<6} | {info}"

    elif ARP in packet:
        op = "Request" if packet[ARP].op == 1 else "Reply"
        return f"ARP {op:<8} | Who has {packet[ARP].pdst} ? Tell {packet[ARP].psrc} ({packet[ARP].hwsrc})"

    return packet.summary()


def start_sniffer(
    filter_expr: str = "",
    count: int = 0,
    timeout: int = None,
    interface: str = None,
    show_details: bool = False,
    output_pcap: str = None
):
    """
    Sniffs network traffic according to the provided parameters.
    Saves packets to output_pcap if specified using wrpcap().
    """
    captured_packets = []

    print("\n" + "=" * 70)
    print(f"[*] Starting Packet Sniffer")
    print(f"    Filter   : {filter_expr if filter_expr else 'All traffic'}")
    print(f"    Interface: {interface if interface else 'Default'}")
    print(f"    Count    : {count if count > 0 else 'Unlimited (Ctrl+C to stop)'}")
    print(f"    Save to  : {output_pcap if output_pcap else 'Not saving'}")
    print("=" * 70)
    print(f"{'Source':<15}    {'Destination':<15} | {'Proto':<6} | Info")
    print("-" * 70)

    def packet_handler(pkt):
        captured_packets.append(pkt)
        summary = format_packet_summary(pkt)
        print(summary)

        if show_details:
            print("\n--- [ Packet Deep Inspection (.show()) ] ---")
            pkt.show()
            print("-" * 50 + "\n")

    try:
        kwargs = {"prn": packet_handler, "store": True}
        if filter_expr:
            kwargs["filter"] = filter_expr
        if count > 0:
            kwargs["count"] = count
        if timeout:
            kwargs["timeout"] = timeout
        if interface:
            kwargs["iface"] = interface

        sniff(**kwargs)

    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user.")

    print("=" * 70)
    print(f"[*] Total captured packets: {len(captured_packets)}")

    if output_pcap and captured_packets:
        os.makedirs(os.path.dirname(output_pcap) or ".", exist_ok=True)
        wrpcap(output_pcap, captured_packets)
        print(f"[+] Packets successfully saved to: {output_pcap}")

    return captured_packets


if __name__ == "__main__":
    import sys
    bpf = sys.argv[1] if len(sys.argv) > 1 else ""
    start_sniffer(filter_expr=bpf, count=10)
