#!/usr/bin/env python3
"""
Custom Packet Crafter & Transmitter Module
Uses Scapy's IP, TCP, UDP, ICMP, Ether, Raw, .show(), send(), and sendp()
to build, inspect, and transmit custom packets at Layer 2 or Layer 3.
"""

from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, send, sendp


def craft_ip_tcp_packet(
    dst_ip: str,
    dport: int = 80,
    src_ip: str = None,
    sport: int = 12345,
    flags: str = "S",
    payload: str = ""
):
    """
    Crafts an IP / TCP packet with customizable fields and optional payload.
    """
    ip_kwargs = {"dst": dst_ip}
    if src_ip:
        ip_kwargs["src"] = src_ip  # IP Spoofing capability

    ip_layer = IP(**ip_kwargs)
    tcp_layer = TCP(sport=sport, dport=dport, flags=flags)
    packet = ip_layer / tcp_layer

    if payload:
        packet = packet / Raw(load=payload.encode())

    return packet


def craft_ip_udp_packet(
    dst_ip: str,
    dport: int = 53,
    src_ip: str = None,
    sport: int = 54321,
    payload: str = "Hello Scapy"
):
    """
    Crafts an IP / UDP packet with custom data payload.
    """
    ip_kwargs = {"dst": dst_ip}
    if src_ip:
        ip_kwargs["src"] = src_ip

    ip_layer = IP(**ip_kwargs)
    udp_layer = UDP(sport=sport, dport=dport)
    packet = ip_layer / udp_layer

    if payload:
        packet = packet / Raw(load=payload.encode())

    return packet


def craft_icmp_packet(dst_ip: str, src_ip: str = None, icmp_type: int = 8, code: int = 0):
    """
    Crafts an IP / ICMP packet (Echo Request by default: type=8, code=0).
    """
    ip_kwargs = {"dst": dst_ip}
    if src_ip:
        ip_kwargs["src"] = src_ip

    ip_layer = IP(**ip_kwargs)
    icmp_layer = ICMP(type=icmp_type, code=code)
    return ip_layer / icmp_layer


def craft_ethernet_packet(
    dst_mac: str = "ff:ff:ff:ff:ff:ff",
    src_mac: str = None,
    inner_packet=None
):
    """
    Wraps an inner Layer 3 packet with an Ethernet Layer 2 header.
    """
    eth_kwargs = {"dst": dst_mac}
    if src_mac:
        eth_kwargs["src"] = src_mac

    eth_layer = Ether(**eth_kwargs)
    if inner_packet:
        return eth_layer / inner_packet
    return eth_layer


def preview_and_send(packet, use_layer2: bool = False, count: int = 1, interval: float = 0.1, iface: str = None):
    """
    Shows packet dissection using .show() and transmits via send() or sendp().
    """
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
