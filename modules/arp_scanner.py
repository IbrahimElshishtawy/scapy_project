#!/usr/bin/env python3
"""
ARP Network Scanner Compatibility Shim.
Delegates to services.scanner.arp_scanner.
"""

import sys
from services.scanner.arp_scanner import scan_network


def print_results(devices: list):
    """Prints discovered devices in a formatted table."""
    print("\n" + "=" * 50)
    print(f"{'IP Address':<20} | {'MAC Address':<20}")
    print("=" * 50)
    if not devices:
        print("No active devices found. Check your subnet or network interface.")
    else:
        for dev in devices:
            print(f"{dev['ip']:<20} | {dev['mac']:<20}")
    print("=" * 50)
    print(f"Total discovered hosts: {len(devices)}\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    results = scan_network(target)
    print_results(results)
