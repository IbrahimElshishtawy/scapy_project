#!/usr/bin/env python3
"""
Custom Packet Crafter & Transmitter Module (Compatibility Shim).
Delegates to services.packet.crafter_service.
"""

from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, send, sendp
from services.packet.crafter_service import (
    craft_tcp_packet,
    craft_udp_packet,
    craft_icmp_packet as _svc_craft_icmp,
    craft_ethernet_packet as _svc_craft_eth,
    send_crafted_packet,
)


def craft_ip_tcp_packet(
    dst_ip: str,
    dport: int = 80,
    src_ip: str = None,
    sport: int = 12345,
    flags: str = "S",
    payload: str = ""
):
    """Crafts an IP / TCP packet with customizable fields and optional payload."""
    return craft_tcp_packet(
        dst_ip=dst_ip,
        dst_port=dport,
        src_ip=src_ip,
        src_port=sport,
        flags=flags,
        payload=payload
    )


def craft_ip_udp_packet(
    dst_ip: str,
    dport: int = 53,
    src_ip: str = None,
    sport: int = 54321,
    payload: str = "Hello Scapy"
):
    """Crafts an IP / UDP packet with custom data payload."""
    return craft_udp_packet(
        dst_ip=dst_ip,
        dst_port=dport,
        src_ip=src_ip,
        src_port=sport,
        payload=payload
    )


def craft_icmp_packet(dst_ip: str, src_ip: str = None, icmp_type: int = 8, code: int = 0):
    """Crafts an IP / ICMP packet."""
    ip_kwargs = {"dst": dst_ip}
    if src_ip:
        ip_kwargs["src"] = src_ip
    return IP(**ip_kwargs) / ICMP(type=icmp_type, code=code)


def craft_ethernet_packet(
    dst_mac: str = "ff:ff:ff:ff:ff:ff",
    src_mac: str = None,
    inner_packet=None
):
    """Wraps an inner Layer 3 packet with an Ethernet Layer 2 header."""
    return _svc_craft_eth(dst_mac=dst_mac, src_mac=src_mac, payload_pkt=inner_packet)


def preview_and_send(packet, use_layer2: bool = False, count: int = 1, interval: float = 0.1, iface: str = None):
    """Shows packet dissection using .show() and transmits via send() or sendp()."""
    print("\n" + "=" * 60)
    print("      CRAFTED PACKET INSPECTION (.show())")
    print("=" * 60)
    packet.show()
    print("=" * 60)

    if use_layer2:
        print(f"\n[*] Transmitting {count} packet(s) at Layer 2 using sendp() ...")
        kwargs = {"count": count, "inter": interval, "verbose": True}
        if iface:
            kwargs["iface"] = iface
        sendp(packet, **kwargs)
    else:
        print(f"\n[*] Transmitting {count} packet(s) at Layer 3 using send() ...")
        send(packet, count=count, inter=interval, verbose=True)

    print("[+] Transmission finished successfully.\n")


if __name__ == "__main__":
    test_pkt = craft_ip_tcp_packet(dst_ip="127.0.0.1", dport=80, flags="S", payload="GET / HTTP/1.1\r\n\r\n")
    preview_and_send(test_pkt, use_layer2=False, count=1)
