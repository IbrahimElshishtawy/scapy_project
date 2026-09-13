"""
Default Gateway Auto-Discovery & Router Service Scanner.
"""

from typing import Tuple, Optional, Dict, List, Any, Callable
from scapy.all import IP, TCP, ICMP, sr1, send
from core.network_utils import get_default_network_context
from core.config import ROUTER_COMMON_SERVICES


def get_default_gateway() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Discovers current network's Default Gateway IP, local IP, and interface name."""
    return get_default_network_context()


def scan_router_ports(
    gateway_ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    callback: Optional[Callable[[int, str, str], None]] = None,
) -> List[Dict[str, Any]]:
    """Scans gateway for router administration and vulnerable ports."""
    if ports is None:
        ports = sorted(list(ROUTER_COMMON_SERVICES.keys()))

    results = []
    for port in ports:
        service_name = ROUTER_COMMON_SERVICES.get(port, "Unknown Router Service")
        packet = IP(dst=gateway_ip) / TCP(dport=port, flags="S")
        reply = sr1(packet, timeout=timeout, verbose=False)

        status = "Filtered"
        if reply is not None and reply.haslayer(TCP):
            flags = reply[TCP].flags
            if flags == 0x12 or flags == "SA":
                status = "Open"
                send(IP(dst=gateway_ip) / TCP(dport=port, flags="R"), verbose=False)
            elif flags == 0x14 or flags == "RA" or "R" in str(flags):
                status = "Closed"

        entry = {"port": port, "status": status, "service": service_name}
        results.append(entry)
        if callback:
            callback(port, status, service_name)

    return results


def evaluate_router_security(scan_results: List[Dict[str, Any]]) -> List[str]:
    """Generates security evaluation warnings based on open ports."""
    alerts = []
    open_ports = {r["port"] for r in scan_results if r["status"] == "Open"}

    if 23 in open_ports:
        alerts.append("[!] HIGH RISK: Telnet port 23 is OPEN on router! Communication is unencrypted.")
    if 7547 in open_ports:
        alerts.append("[!] WARNING: Port 7547 (TR-069) is OPEN. Often targeted in router exploits.")
    if 80 in open_ports and 443 not in open_ports:
        alerts.append("[!] ADVISORY: Router Web Admin is on HTTP (Port 80) without HTTPS.")
    if 1900 in open_ports:
        alerts.append("[!] NOTE: UPnP port 1900 is OPEN. Devices on LAN can automatically map WAN ports.")

    if not alerts:
        alerts.append("[+] Router port security posture looks clean among tested services.")

    return alerts
