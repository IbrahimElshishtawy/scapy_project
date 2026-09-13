#!/usr/bin/env python3
"""
Scapy Network Toolkit - CLI Launcher.
Enterprise Layered Architecture v2.0.
"""

import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.privileges import check_startup_privileges
from cli.banner import get_banner
from cli.menu import run_interactive_menu


def main():
    check_startup_privileges()
    print(get_banner())
    run_interactive_menu()


if __name__ == "__main__":
    main()
