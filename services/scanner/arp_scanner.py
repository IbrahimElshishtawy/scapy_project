"""
ARP Broadcast Network Scanner Service (Layer 2).
"""

from typing import List, Dict
from scapy.all import Ether, ARP, srp
from core.network_utils import is_valid_subnet


def scan_network(ip_range: str = "192.168.1.0/24", timeout: int = 2) -> List[Dict[str, str]]:
    """
    Sends ARP broadcast to discover active hosts and MAC addresses on the local subnet.
    """
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=timeout, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
    return devices
