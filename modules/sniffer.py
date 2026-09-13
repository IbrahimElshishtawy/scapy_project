#!/usr/bin/env python3
"""
Packet Sniffer & Capture Module (Compatibility Shim).
Delegates to services.packet.sniffer_service.
"""

import os
from services.packet.sniffer_service import (
    format_packet_summary,
    capture_packets,
    save_packets_to_pcap
)


def start_sniffer(
    filter_expr: str = "",
    count: int = 0,
    timeout: int = None,
    interface: str = None,
    show_details: bool = False,
    output_pcap: str = None
):
    """Sniffs network traffic and prints/saves packets."""
    captured_packets = []

    print("\n" + "=" * 70)
    print("[*] Starting Packet Sniffer")
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
        from scapy.all import sniff
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
        save_packets_to_pcap(captured_packets, output_pcap)
        print(f"[+] Packets successfully saved to: {output_pcap}")

    return captured_packets


if __name__ == "__main__":
    import sys
    bpf = sys.argv[1] if len(sys.argv) > 1 else ""
    start_sniffer(filter_expr=bpf, count=10)
