#!/usr/bin/env python3
"""
Port Scanner & Host Reachability Module
Uses Scapy's IP, ICMP, TCP, UDP, sr1, and send to probe hosts and open ports.
"""

from scapy.all import IP, ICMP, TCP, UDP, sr1, send

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8000, 8080]


def icmp_ping(target_ip: str, timeout: int = 2, verbose: bool = False):
    """
    Sends an ICMP Echo Request to target_ip using IP() / ICMP() and sr1().
    Returns (True, response_packet) if host is up, else (False, None).
    """
    packet = IP(dst=target_ip) / ICMP()
    reply = sr1(packet, timeout=timeout, verbose=verbose)

    if reply and reply.haslayer(ICMP):
        # ICMP type 0 is Echo Reply
        if reply[ICMP].type == 0:
            return True, reply
    return False, None


def tcp_syn_scan_port(target_ip: str, port: int, timeout: int = 1, verbose: bool = False):
    """
    Performs a stealth TCP SYN scan on a specific port.
    Sends SYN and inspects response flags (SYN-ACK=Open, RST=Closed).
    """
    # 1. Build IP and TCP layers with SYN flag
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

    # 2. Send and wait for 1 response packet using sr1()
    reply = sr1(syn_packet, timeout=timeout, verbose=verbose)

    if reply is None:
        return "Filtered"
    elif reply.haslayer(TCP):
        flags = reply[TCP].flags
        # 0x12 = SYN + ACK
        if flags == 0x12 or flags == "SA":
            # Send RST to tear down half-open connection cleanly
            rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
            send(rst_packet, verbose=False)
            return "Open"
        # 0x14 = RST + ACK
        elif flags == 0x14 or flags == "RA" or "R" in str(flags):
            return "Closed"
    elif reply.haslayer(ICMP):
        return "Filtered"

    return "Unknown"


def scan_ports(target_ip: str, ports: list = None, timeout: int = 1):
    """
    Scans multiple ports on target_ip and prints summary results.
    """
    if ports is None:
        ports = COMMON_PORTS

    print(f"\n[*] Starting TCP SYN Scan on {target_ip} for {len(ports)} ports...")
    print("=" * 45)
    print(f"{'Port':<10} | {'Status':<15} | {'Service/Protocol':<15}")
    print("=" * 45)

    results = {}
    for port in ports:
        status = tcp_syn_scan_port(target_ip, port, timeout=timeout)
        results[port] = status
        if status == "Open":
            print(f"{port:<10} | \033[92m{status:<15}\033[0m | TCP")
        elif status == "Filtered":
            print(f"{port:<10} | \033[93m{status:<15}\033[0m | TCP")
        else:
            print(f"{port:<10} | \033[90m{status:<15}\033[0m | TCP")

    print("=" * 45)
    open_count = sum(1 for s in results.values() if s == "Open")
    print(f"Scan complete: {open_count} open port(s) found.\n")
    return results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    is_up, resp = icmp_ping(target)
    print(f"Host {target} is {'UP' if is_up else 'DOWN/Unresponsive'}")
    if is_up:
        scan_ports(target, [22, 80, 443, 8080])
