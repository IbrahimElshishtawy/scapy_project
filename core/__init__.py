"""
Core module exports for Scapy Network Toolkit.
"""

from .config import (
    BASE_DIR,
    CAPTURES_DIR,
    COMMON_PORTS,
    ROUTER_COMMON_SERVICES,
    COLORS,
    DEFAULT_TIMEOUT,
)
from .privileges import is_root, require_root, check_startup_privileges
from .logger import logger
from .network_utils import (
    is_valid_ip,
    is_valid_subnet,
    resolve_hostname,
    get_active_interfaces,
    get_default_network_context,
)

__all__ = [
    "BASE_DIR",
    "CAPTURES_DIR",
    "COMMON_PORTS",
    "ROUTER_COMMON_SERVICES",
    "COLORS",
    "DEFAULT_TIMEOUT",
    "is_root",
    "require_root",
    "check_startup_privileges",
    "logger",
    "is_valid_ip",
    "is_valid_subnet",
    "resolve_hostname",
    "get_active_interfaces",
    "get_default_network_context",
]
