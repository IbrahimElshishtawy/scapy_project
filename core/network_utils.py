"""
Network Utilities: IP validation, interface inspection, socket helpers.
"""

import ipaddress
import socket
from typing import Optional, Tuple
from scapy.all import conf, get_if_list


def is_valid_ip(ip_str: str) -> bool:
    """Validates whether a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_valid_subnet(subnet_str: str) -> bool:
    """Validates whether a string is a valid IPv4 network/CIDR."""
    try:
        ipaddress.IPv4Network(subnet_str.strip(), strict=False)
        return True
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolves a hostname to an IPv4 address. Returns None on failure."""
    try:
        return socket.gethostbyname(hostname.strip())
    except socket.gaierror:
        return None


def get_active_interfaces() -> list:
    """Returns list of active local network interfaces."""
    try:
        return get_if_list()
    except Exception:
        return []


def get_default_network_context() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Returns (gateway_ip, local_ip, interface_name) for default route.
    """
    try:
        route = conf.route.route("0.0.0.0")
        if route and route[2] != "0.0.0.0":
            iface = route[0]
            local_ip = route[1]
            gateway_ip = route[2]
            return gateway_ip, local_ip, iface
    except Exception:
        pass
    return None, None, None
