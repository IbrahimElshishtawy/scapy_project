#!/usr/bin/env python3
"""
ARP Network Scanner Module
Uses Scapy's ARP, Ether, and srp to discover active hosts on a local subnet.
"""

from scapy.all import ARP, Ether, srp


def scan_network(ip_range: str, timeout: int = 2, verbose: bool = False):
    """
    Scans a given IP range or CIDR subnet (e.g., 192.168.1.1/24) using ARP requests.
    Returns a list of dictionaries with IP and MAC addresses of active hosts.
    """
    print(f"\n[*] Sending ARP broadcast to {ip_range} ...")

    # 1. Build Ethernet broadcast frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # 2. Build ARP request for the target IP range
    arp_request = ARP(pdst=ip_range)

    # 3. Stack layers
    packet = broadcast / arp_request

    # 4. Send and receive packets at Layer 2 using srp()
    answered_list, _ = srp(packet, timeout=timeout, verbose=verbose)

    devices = []
    for sent, received in answered_list:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


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
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    results = scan_network(target)
    print_results(results)
