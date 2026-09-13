"""
Packet Crafter & Forging Service (Layer 2 & Layer 3).
"""

from typing import Optional, Any
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, send, sendp


def craft_tcp_packet(
    dst_ip: str,
    dst_port: int,
    src_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    flags: str = "S",
    payload: str = "",
):
    """Crafts custom Layer 3 IP + TCP packet with optional payload and spoofed source IP."""
    ip_kwargs = {"dst": dst_ip}
    if src_ip and src_ip.strip():
        ip_kwargs["src"] = src_ip.strip()

    tcp_kwargs = {"dport": int(dst_port), "flags": flags}
    if src_port:
        tcp_kwargs["sport"] = int(src_port)

    pkt = IP(**ip_kwargs) / TCP(**tcp_kwargs)
    if payload:
        pkt = pkt / Raw(load=payload.encode("utf-8"))
    return pkt


def craft_udp_packet(
    dst_ip: str,
    dst_port: int,
    src_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    payload: str = "",
):
    """Crafts custom Layer 3 IP + UDP packet with optional payload."""
    ip_kwargs = {"dst": dst_ip}
    if src_ip and src_ip.strip():
        ip_kwargs["src"] = src_ip.strip()

    udp_kwargs = {"dport": int(dst_port)}
    if src_port:
        udp_kwargs["sport"] = int(src_port)

    pkt = IP(**ip_kwargs) / UDP(**udp_kwargs)
    if payload:
        pkt = pkt / Raw(load=payload.encode("utf-8"))
    return pkt


def craft_icmp_packet(
    dst_ip: str,
    src_ip: Optional[str] = None,
    icmp_type: int = 8,
    payload: str = "ScapyToolkitPing",
):
    """Crafts custom ICMP packet (Echo Request)."""
    ip_kwargs = {"dst": dst_ip}
    if src_ip and src_ip.strip():
        ip_kwargs["src"] = src_ip.strip()

    pkt = IP(**ip_kwargs) / ICMP(type=icmp_type)
    if payload:
        pkt = pkt / Raw(load=payload.encode("utf-8"))
    return pkt


def craft_ethernet_packet(
    dst_mac: str,
    src_mac: Optional[str] = None,
    payload_pkt: Optional[Any] = None,
):
    """Crafts custom Layer 2 Ethernet Frame."""
    kwargs = {"dst": dst_mac}
    if src_mac and src_mac.strip():
        kwargs["src"] = src_mac.strip()
    eth = Ether(**kwargs)
    return eth / payload_pkt if payload_pkt else eth


def send_crafted_packet(packet: Any, count: int = 1, is_layer2: bool = False):
    """Sends packet via send() (L3) or sendp() (L2)."""
    if is_layer2 or packet.haslayer(Ether):
        sendp(packet, count=count, verbose=False)
    else:
        send(packet, count=count, verbose=False)
