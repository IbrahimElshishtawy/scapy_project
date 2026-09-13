#!/usr/bin/env python3
"""
Scapy Network Toolkit - Desktop GUI Launcher.
Enterprise Layered Architecture v2.0.
"""

import os
import sys

# Ensure project root is discoverable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import tkinter as tk
    from gui.app import launch_gui
except ImportError as err:
    print("\n" + "=" * 70)
    print("[-] Error: Tkinter is not installed on your system.")
    print("    To install Tkinter on Ubuntu/Debian, please run:")
    print("    sudo apt update && sudo apt install -y python3-tk")
    print("=" * 70 + "\n")
    sys.exit(1)


def main():
    launch_gui()


if __name__ == "__main__":
    main()
