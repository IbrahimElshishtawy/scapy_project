"""
ICMP Ping & TCP Stealth SYN Port Scanner Service.
"""

from typing import Dict, List, Optional, Callable, Tuple, Any
from scapy.all import IP, TCP, ICMP, sr1, send
from core.config import COMMON_PORTS


def icmp_ping(target_ip: str, timeout: float = 1.5) -> bool:
    """Sends ICMP Echo Request and checks for Echo Reply."""
    packet = IP(dst=target_ip) / ICMP()
    reply = sr1(packet, timeout=timeout, verbose=False)
    return bool(reply and reply.haslayer(ICMP) and reply[ICMP].type == 0)


def tcp_syn_scan_port(target_ip: str, port: int, timeout: float = 1.0) -> Tuple[int, str, str]:
    """
    Scans a single TCP port using Stealth SYN scan.
    Returns (port, status, service_name).
    Status is 'Open', 'Closed', or 'Filtered'.
    """
    service_name = COMMON_PORTS.get(port, "Unknown Service")
    packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    reply = sr1(packet, timeout=timeout, verbose=False)

    if reply is None:
        return port, "Filtered", service_name

    if reply.haslayer(TCP):
        flags = reply[TCP].flags
        if flags == 0x12 or flags == "SA":  # SYN-ACK
            # Send RST to politely tear down half-open connection
            rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
            send(rst_packet, verbose=False)
            return port, "Open", service_name
        elif flags == 0x14 or flags == "RA" or "R" in str(flags):  # RST-ACK
            return port, "Closed", service_name

    return port, "Filtered", service_name


def scan_target_ports(
    target_ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    callback: Optional[Callable[[int, str, str], None]] = None,
) -> List[Dict[str, Any]]:
    """Scans multiple TCP ports on target_ip."""
    if ports is None:
        ports = sorted(list(COMMON_PORTS.keys()))

    results = []
    for port in ports:
        port_num, status, service = tcp_syn_scan_port(target_ip, port, timeout=timeout)
        entry = {"port": port_num, "status": status, "service": service}
        results.append(entry)
        if callback:
            callback(port_num, status, service)
    return results
