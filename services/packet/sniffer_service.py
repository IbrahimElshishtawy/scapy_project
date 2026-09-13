"""
Live Packet Sniffer & PCAP Exporter Service.
"""

from datetime import datetime
from typing import Callable, List, Optional, Dict, Any
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP
from core.config import CAPTURES_DIR
from core.logger import logger


def format_packet_summary(packet) -> str:
    """Formats a concise one-line summary for a packet."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP({proto})")
        info = ""
        if packet.haslayer(TCP):
            info = f"Port {packet[TCP].sport} -> {packet[TCP].dport} [Flags: {packet[TCP].flags}]"
        elif packet.haslayer(UDP):
            info = f"Port {packet[UDP].sport} -> {packet[UDP].dport} Len={len(packet[UDP])}"
        elif packet.haslayer(ICMP):
            info = f"Type={packet[ICMP].type} Code={packet[ICMP].code}"
        return f"[{timestamp}] {proto_name:<6} {src:<15} -> {dst:<15} | {info}"
    elif packet.haslayer(ARP):
        op = "Request" if packet[ARP].op == 1 else "Reply"
        return f"[{timestamp}] ARP    {packet[ARP].psrc} -> {packet[ARP].pdst} ({op})"
    return f"[{timestamp}] {packet.summary()}"


def extract_packet_meta(packet, index: int = 0) -> Dict[str, Any]:
    """Extracts structured metadata from packet for tables / UI views."""
    src = "Unknown"
    dst = "Unknown"
    proto = "Other"
    info = packet.summary()

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        if packet.haslayer(TCP):
            proto = "TCP"
            info = f"{packet[TCP].sport} -> {packet[TCP].dport} [{packet[TCP].flags}]"
        elif packet.haslayer(UDP):
            proto = "UDP"
            info = f"{packet[UDP].sport} -> {packet[UDP].dport} (len={len(packet[UDP])})"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            info = f"Type {packet[ICMP].type} Code {packet[ICMP].code}"
        else:
            proto = f"IP({packet[IP].proto})"
    elif packet.haslayer(ARP):
        proto = "ARP"
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
        info = "Who has?" if packet[ARP].op == 1 else "ARP Reply"

    return {
        "index": index,
        "src": src,
        "dst": dst,
        "proto": proto,
        "info": info,
        "packet": packet,
    }


def capture_packets(
    filter_expr: str = "",
    count: int = 0,
    timeout: Optional[int] = None,
    callback: Optional[Callable] = None,
    stop_filter: Optional[Callable] = None,
) -> List[Any]:
    """
    Captures live packets with optional BPF filter, count, timeout, and per-packet callback.
    """
    kwargs = {"count": count}
    if filter_expr.strip():
        kwargs["filter"] = filter_expr.strip()
    if timeout:
        kwargs["timeout"] = timeout
    if callback:
        kwargs["prn"] = callback
    if stop_filter:
        kwargs["stop_filter"] = stop_filter

    return sniff(**kwargs)


def save_packets_to_pcap(packets: List[Any], filepath: Optional[str] = None) -> str:
    """Saves captured packet list to .pcap file."""
    if not filepath:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = str(CAPTURES_DIR / f"capture_{timestamp}.pcap")
    wrpcap(filepath, packets)
    return filepath
