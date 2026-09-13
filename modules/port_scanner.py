#!/usr/bin/env python3
"""
Port Scanner & Host Reachability Module (Compatibility Shim).
Delegates to services.scanner.port_scanner.
"""

import sys
from scapy.all import IP, ICMP, sr1
from services.scanner.port_scanner import tcp_syn_scan_port as _svc_syn_scan, COMMON_PORTS as _SVC_COMMON_PORTS

COMMON_PORTS = sorted(list(_SVC_COMMON_PORTS.keys()))


def icmp_ping(target_ip: str, timeout: int = 2, verbose: bool = False):
    """
    Sends an ICMP Echo Request to target_ip using IP() / ICMP() and sr1().
    Returns (True, response_packet) if host is up, else (False, None).
    """
    packet = IP(dst=target_ip) / ICMP()
    reply = sr1(packet, timeout=timeout, verbose=verbose)
    if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
        return True, reply
    return False, None


def tcp_syn_scan_port(target_ip: str, port: int, timeout: int = 1, verbose: bool = False):
    """
    Legacy wrapper returning status string ('Open', 'Closed', 'Filtered').
    """
    _, status, _ = _svc_syn_scan(target_ip, port, timeout=timeout)
    return status


def scan_ports(target_ip: str, ports: list = None, timeout: int = 1):
    """Scans multiple ports on target_ip and prints summary results."""
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
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    is_up, resp = icmp_ping(target)
    print(f"Host {target} is {'UP' if is_up else 'DOWN/Unresponsive'}")
    if is_up:
        scan_ports(target, [22, 80, 443, 8080])
