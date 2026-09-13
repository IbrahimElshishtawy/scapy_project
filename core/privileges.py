"""
Privilege and Permission Verification Utilities.
"""

import os
import sys
from .config import COLORS


def is_root() -> bool:
    """Returns True if the current process is running with root/superuser privileges."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root(action_name: str = "This operation") -> bool:
    """
    Checks if running as root. If not, prints a warning message.
    Returns True if root, False otherwise.
    """
    if not is_root():
        c_yellow = COLORS["YELLOW"]
        c_bold = COLORS["BOLD"]
        c_reset = COLORS["RESET"]
        print(f"\n{c_yellow}[!] Warning: {action_name} requires superuser (root/sudo) privileges.{c_reset}")
        print(f"{c_yellow}    Raw socket creation, packet sniffing, and network injection may fail without root.{c_reset}")
        print(f"{c_yellow}    To run with privileges: {c_bold}sudo {sys.executable} {' '.join(sys.argv)}{c_reset}\n")
        return False
    return True


def check_startup_privileges():
    """Prints startup privilege advisory banner."""
    if not is_root():
        c_yellow = COLORS["YELLOW"]
        c_bold = COLORS["BOLD"]
        c_reset = COLORS["RESET"]
        print(f"{c_yellow}[!] Advisory: Running without root privileges.{c_reset}")
        print(f"{c_yellow}    Packet sniffing, raw injection, and Wi-Fi password extraction require root.{c_reset}")
        print(f"{c_yellow}    Run with: {c_bold}sudo ./venv/bin/python main.py{c_reset}\n")
