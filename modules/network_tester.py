#!/usr/bin/env python3
"""
Network-Wide Multi-Host Port Scanner & Service Tester Module.
Interactive CLI Presentation & Compatibility Layer.
"""

import sys
import time
from typing import Optional, List, Dict, Any

from core.config import COLORS
from services.scanner.network_tester import (
    detect_local_network_context,
    discover_active_hosts,
    test_service_port,
    scan_and_test_host,
    run_network_audit,
    DEFAULT_TEST_PORTS,
)


def print_network_context_banner(ctx: Dict[str, Any]):
    """Prints detected local network information in a stylized card."""
    print(f"\n{COLORS['CYAN']}╔══════════════════════════════════════════════════════════════════════════════╗{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['BOLD']}🌐 Local Network Environment Auto-Detection{COLORS['RESET']:<60} {COLORS['CYAN']}║{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}╠══════════════════════════════════════════════════════════════════════════════╣{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}║{COLORS['RESET']}  • Active Interface : {COLORS['GREEN']}{ctx['iface']:<50}{COLORS['RESET']} {COLORS['CYAN']}║{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}║{COLORS['RESET']}  • Local IP Address : {COLORS['GREEN']}{ctx['local_ip']:<50}{COLORS['RESET']} {COLORS['CYAN']}║{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}║{COLORS['RESET']}  • Subnet Range     : {COLORS['YELLOW']}{ctx['subnet_cidr']:<50}{COLORS['RESET']} {COLORS['CYAN']}║{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}║{COLORS['RESET']}  • Default Gateway  : {COLORS['GREEN']}{ctx['gateway_ip']:<50}{COLORS['RESET']} {COLORS['CYAN']}║{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}║{COLORS['RESET']}  • Gateway MAC      : {COLORS['PURPLE']}{ctx['gateway_mac']:<50}{COLORS['RESET']} {COLORS['CYAN']}║{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}╚══════════════════════════════════════════════════════════════════════════════╝{COLORS['RESET']}")


def run_interactive_network_tester():
    """CLI interactive wizard to sweep local network, scan ports, and test services."""
    ctx = detect_local_network_context()
    print_network_context_banner(ctx)

    print(f"\n{COLORS['BOLD']}Options:{COLORS['RESET']}")
    print(f"  {COLORS['GREEN']}1){COLORS['RESET']} 🚀 Auto-audit entire current subnet ({ctx['subnet_cidr']})")
    print(f"  {COLORS['GREEN']}2){COLORS['RESET']} 🎯 Scan a custom subnet (e.g. 192.168.1.0/24, 10.0.0.0/24)")
    print(f"  {COLORS['GREEN']}3){COLORS['RESET']} 🔍 Scan single target IP with full deep service test")

    choice = input(f"\n{COLORS['BOLD']}Select option [1-3] (default: 1): {COLORS['RESET']}").strip()
    if not choice:
        choice = "1"

    target_subnet = None
    single_ip = None

    if choice == "1":
        target_subnet = ctx["subnet_cidr"]
    elif choice == "2":
        target_subnet = input(f"Enter custom subnet CIDR (e.g. {ctx['subnet_cidr']}): ").strip()
        if not target_subnet:
            target_subnet = ctx["subnet_cidr"]
    elif choice == "3":
        single_ip = input(f"Enter target IP (e.g. {ctx['gateway_ip']}): ").strip()
        if not single_ip:
            single_ip = ctx["gateway_ip"]
    else:
        print(f"{COLORS['RED']}[-] Invalid choice.{COLORS['RESET']}")
        return

    # Port selection
    print(f"\n{COLORS['BOLD']}Port Profile Selection:{COLORS['RESET']}")
    print(f"  {COLORS['CYAN']}1){COLORS['RESET']} Common Core & Router Services ({len(DEFAULT_TEST_PORTS)} ports: Web, SSH, FTP, DNS, SMB, Databases)")
    print(f"  {COLORS['CYAN']}2){COLORS['RESET']} Web Administration only (80, 443, 8080, 8443, 5000, 8888)")
    print(f"  {COLORS['CYAN']}3){COLORS['RESET']} Custom comma-separated ports")

    pport_choice = input("Select port profile [1-3] (default: 1): ").strip() or "1"
    target_ports = DEFAULT_TEST_PORTS

    if pport_choice == "2":
        target_ports = [80, 443, 5000, 8000, 8080, 8443, 8888]
    elif pport_choice == "3":
        ports_str = input("Enter ports separated by comma (e.g. 21, 22, 80, 443, 3306): ").strip()
        if ports_str:
            try:
                target_ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
            except Exception:
                print("[-] Invalid ports, using default.")
                target_ports = DEFAULT_TEST_PORTS

    print(f"\n{COLORS['CYAN']}[*] Selected {len(target_ports)} ports to inspect per host.{COLORS['RESET']}")

    # Single host path
    if single_ip:
        print(f"\n{COLORS['BOLD']}[*] Auditing target host: {COLORS['GREEN']}{single_ip}{COLORS['RESET']} ...")
        t_start = time.time()
        open_ports = scan_and_test_host(single_ip, ports=target_ports, timeout=1.2)
        duration = round(time.time() - t_start, 2)
        print_host_report(single_ip, "Target Host", "Single Target", open_ports, duration)
        return

    # Subnet path
    print(f"\n{COLORS['BOLD']}[*] Step 1: Sweeping subnet {target_subnet} for live hosts ...{COLORS['RESET']}")

    def on_host(h):
        gw_label = " [ROUTER / GATEWAY]" if h["is_gateway"] else ""
        local_label = " [THIS MACHINE]" if h["is_local"] else ""
        print(f"  {COLORS['GREEN']}[+]{COLORS['RESET']} Discovered: {COLORS['BOLD']}{h['ip']:<15}{COLORS['RESET']} | MAC: {h['mac']:<17} | {h['hostname']}{COLORS['YELLOW']}{gw_label}{local_label}{COLORS['RESET']}")

    t_start = time.time()
    hosts = discover_active_hosts(subnet=target_subnet, timeout=2.0, callback=on_host)
    print(f"\n{COLORS['GREEN']}[+] Step 1 Complete: Found {len(hosts)} active host(s) on {target_subnet}!{COLORS['RESET']}")

    if not hosts:
        print(f"{COLORS['YELLOW']}[!] No active hosts responded on {target_subnet}.{COLORS['RESET']}")
        return

    # Step 2: Port and Service Testing
    print(f"\n{COLORS['BOLD']}[*] Step 2: Parallel Port Scanning & Service Testing ({len(target_ports)} ports/host) ...{COLORS['RESET']}")
    print("=" * 95)

    total_open = 0
    host_reports = []

    for idx, host in enumerate(hosts, 1):
        hip = host["ip"]
        role = " (Default Gateway)" if host["is_gateway"] else (" (Local Host)" if host["is_local"] else "")
        print(f"\n{COLORS['BOLD']}[{idx}/{len(hosts)}] Scanning & Testing Host: {COLORS['CYAN']}{hip}{COLORS['RESET']}{role} | MAC: {host['mac']}")

        h_start = time.time()
        open_ports = scan_and_test_host(hip, ports=target_ports, timeout=1.0)
        h_duration = round(time.time() - h_start, 2)

        total_open += len(open_ports)
        host_reports.append((host, open_ports, h_duration))

        if not open_ports:
            print(f"    {COLORS['YELLOW']}↳ No open ports detected among scanned list.{COLORS['RESET']}")
        else:
            for p in open_ports:
                risk_color = COLORS['RED'] if "HIGH" in p["risk_level"] else (COLORS['YELLOW'] if "MEDIUM" in p["risk_level"] else COLORS['GREEN'])
                print(f"    {COLORS['GREEN']}✔ Port {p['port']:<5}{COLORS['RESET']} | {p['service']:<18} | {p['latency_ms']}ms | {risk_color}[{p['risk_level']}]{COLORS['RESET']}")
                print(f"      {COLORS['CYAN']}↳ Banner / Probe:{COLORS['RESET']} {p['banner']}")

    total_duration = round(time.time() - t_start, 2)
    print_network_executive_summary(target_subnet, hosts, total_open, total_duration, host_reports)


def print_host_report(ip: str, mac: str, hostname: str, open_ports: List[Dict[str, Any]], duration: float):
    """Displays formatted table for a single host."""
    print("=" * 95)
    print(f"Host: {ip} | MAC: {mac} | Name: {hostname} | Scan Time: {duration}s")
    print("=" * 95)
    if not open_ports:
        print(f"{COLORS['YELLOW']}[!] No open ports found on this host among scanned list.{COLORS['RESET']}")
        return

    print(f"{'Port':<7} | {'Service':<18} | {'Latency':<8} | {'Risk':<10} | {'Banner / Probe Result'}")
    print("-" * 95)
    for p in open_ports:
        risk_color = COLORS['RED'] if "HIGH" in p["risk_level"] else (COLORS['YELLOW'] if "MEDIUM" in p["risk_level"] else COLORS['GREEN'])
        print(f"{p['port']:<7} | {p['service']:<18} | {p['latency_ms']}ms | {risk_color}{p['risk_level']:<10}{COLORS['RESET']} | {p['banner']}")
    print("=" * 95)


def print_network_executive_summary(
    subnet: str,
    hosts: List[Dict[str, Any]],
    total_open: int,
    duration: float,
    reports: List[Any]
):
    """Displays final executive summary table and security advisories."""
    print("\n" + "=" * 95)
    print(f"{COLORS['BOLD']}📊 NETWORK AUDIT EXECUTIVE SUMMARY & SERVICE INVENTORY{COLORS['RESET']}")
    print("=" * 95)
    print(f"Target Subnet      : {subnet}")
    print(f"Total Hosts Live   : {len(hosts)}")
    print(f"Total Open Ports   : {total_open}")
    print(f"Execution Duration : {duration} seconds")
    print("-" * 95)
    print(f"{'IP Address':<16} | {'MAC Address':<18} | {'Role':<16} | {'Open Ports'}")
    print("-" * 95)

    high_risk_alerts = []

    for host, open_ports, _ in reports:
        role = "Router / Gateway" if host["is_gateway"] else ("Local Machine" if host["is_local"] else "Workstation/Device")
        ports_summary = ", ".join([str(p["port"]) for p in open_ports]) if open_ports else "None open"
        print(f"{host['ip']:<16} | {host['mac']:<18} | {role:<16} | {COLORS['GREEN']}{ports_summary}{COLORS['RESET']}")

        for p in open_ports:
            if "HIGH" in p["risk_level"]:
                high_risk_alerts.append(f"Host {host['ip']} has HIGH RISK port {p['port']} ({p['service']}) open: {p['banner']}")
            elif p["port"] == 80 and not any(op["port"] == 443 for op in open_ports):
                high_risk_alerts.append(f"Host {host['ip']} serves unencrypted HTTP (Port 80) with no HTTPS (Port 443).")

    if high_risk_alerts:
        print("\n" + f"{COLORS['RED']}{COLORS['BOLD']}⚠️  SECURITY ADVISORIES & OBSERVATIONS:{COLORS['RESET']}")
        for alert in high_risk_alerts:
            print(f"  {COLORS['RED']}•{COLORS['RESET']} {alert}")
    else:
        print(f"\n{COLORS['GREEN']}[+] No critical unencrypted high-risk ports (like Telnet) were detected.{COLORS['RESET']}")

    print("=" * 95 + "\n")
