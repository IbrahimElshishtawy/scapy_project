"""
Interactive CLI Controller & Menu Loop for Scapy Network Toolkit.
"""

import os
import sys
import subprocess
from datetime import datetime

from core.config import COLORS, CAPTURES_DIR
from core.privileges import require_root
from core.logger import logger
from cli.banner import get_banner

from modules.arp_scanner import scan_network, print_results
from modules.port_scanner import icmp_ping, scan_ports
from modules.sniffer import start_sniffer
from modules.pcap_analyzer import load_pcap, print_pcap_statistics, list_packets_summary, inspect_packet
from modules.packet_crafter import (
    craft_ip_tcp_packet,
    craft_ip_udp_packet,
    craft_icmp_packet,
    craft_ethernet_packet,
    preview_and_send
)
from modules.wifi_manager import (
    scan_nearby_wifi,
    print_wifi_scan_results,
    get_saved_wifi_passwords,
    print_saved_passwords,
    connect_to_wifi,
    audit_password_strength
)
from modules.gateway_scanner import (
    auto_audit_current_router,
    get_default_gateway,
    scan_router_ports
)
from modules.wifi_sniffer import live_beacon_sniff, analyze_wireless_pcap
from modules.http_recon import run_interactive_http_menu
from modules.ssh_manager import run_interactive_ssh_menu
from modules.network_tester import run_interactive_network_tester


def handle_sniffer():
    print(f"\n{COLORS['BOLD']}--- [ Live Packet Sniffer (sniff & wrpcap) ] ---{COLORS['RESET']}")
    filter_expr = input("Enter BPF filter (e.g., 'tcp', 'icmp', 'port 80', or press Enter for all): ").strip()
    count_in = input("Enter packet count (0 for continuous capture until Ctrl+C): ").strip()
    count = int(count_in) if count_in.isdigit() else 0
    show_details = input("Display full deep inspection (.show()) for every packet? (y/N): ").strip().lower() == 'y'
    save_pcap = input("Save captured packets to .pcap file? (Y/n): ").strip().lower() != 'n'

    output_pcap = None
    if save_pcap:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = str(CAPTURES_DIR / f"sniff_{timestamp}.pcap")
        chosen_path = input(f"Enter file path (default: {default_filename}): ").strip()
        output_pcap = chosen_path if chosen_path else default_filename

    start_sniffer(
        filter_expr=filter_expr,
        count=count,
        show_details=show_details,
        output_pcap=output_pcap
    )


def handle_pcap_analyzer():
    print(f"\n{COLORS['BOLD']}--- [ PCAP Capture Reader & Deep Dissection (rdpcap & .show()) ] ---{COLORS['RESET']}")
    default_pcap = str(CAPTURES_DIR / "sample_test.pcap")
    pcap_path = input(f"Enter path to .pcap file (default: {default_pcap}): ").strip()
    if not pcap_path:
        pcap_path = default_pcap

    packets = load_pcap(pcap_path)
    if not packets:
        return

    print_pcap_statistics(packets)
    list_packets_summary(packets, limit=15)

    while True:
        choice = input("Enter packet index to inspect (.show()) or 'q' to return: ").strip().lower()
        if choice in ['q', 'exit', '']:
            break
        if choice.isdigit():
            inspect_packet(packets, int(choice))
        else:
            print("[-] Invalid input.")


def handle_arp_scanner():
    print(f"\n{COLORS['BOLD']}--- [ ARP Local Network Discovery Scanner (ARP, Ether, srp) ] ---{COLORS['RESET']}")
    subnet = input("Enter local subnet CIDR (e.g., '192.168.1.0/24' or press Enter for default): ").strip()
    if not subnet:
        subnet = "192.168.1.0/24"
    results = scan_network(subnet)
    print_results(results)


def handle_port_scanner():
    print(f"\n{COLORS['BOLD']}--- [ ICMP Ping & TCP Stealth SYN Port Scanner (sr1) ] ---{COLORS['RESET']}")
    target = input("Enter target IP or hostname (default: 127.0.0.1): ").strip()
    if not target:
        target = "127.0.0.1"

    print(f"[*] Testing reachability with ICMP Echo Request (Ping) ...")
    is_up, _ = icmp_ping(target)
    if is_up:
        print(f"\033[92m[+] Host {target} is UP and responding to Ping!\033[0m")
    else:
        print(f"\033[93m[!] Host {target} did not reply to ICMP Ping (may be offline or blocking ICMP).\033[0m")

    do_scan = input("Proceed with TCP SYN Port Scan? (Y/n): ").strip().lower() != 'n'
    if do_scan:
        ports_input = input("Enter comma-separated ports (or press Enter for common ports): ").strip()
        custom_ports = None
        if ports_input:
            try:
                custom_ports = [int(p.strip()) for p in ports_input.split(",") if p.strip().isdigit()]
            except ValueError:
                print("[-] Invalid port list, using common ports.")
                custom_ports = None
        scan_ports(target, ports=custom_ports)


def handle_packet_crafter():
    print(f"\n{COLORS['BOLD']}--- [ Custom Packet Crafter & Transmitter (IP, TCP, UDP, send, sendp) ] ---{COLORS['RESET']}")
    print("1) Craft IP + TCP packet")
    print("2) Craft IP + UDP packet")
    print("3) Craft ICMP Echo Request packet")
    print("4) Craft Layer 2 Ethernet Frame")
    ptype = input("Select packet type [1-4]: ").strip()

    dst_ip = input("Enter Destination IP (e.g., 127.0.0.1): ").strip() or "127.0.0.1"
    src_ip = input("Enter Source IP (IP Spoofing) or press Enter for real IP: ").strip() or None

    packet = None
    use_l2 = False

    if ptype == "1":
        dport = int(input("Enter Destination Port (default: 80): ").strip() or "80")
        flags = input("Enter TCP Flags (e.g., 'S' for SYN, 'A' for ACK, default: 'S'): ").strip().upper() or "S"
        payload = input("Enter optional text payload: ").strip()
        packet = craft_ip_tcp_packet(dst_ip=dst_ip, dport=dport, src_ip=src_ip, flags=flags, payload=payload)
    elif ptype == "2":
        dport = int(input("Enter Destination Port (default: 53): ").strip() or "53")
        payload = input("Enter optional text payload (default: 'Hello Scapy'): ").strip() or "Hello Scapy"
        packet = craft_ip_udp_packet(dst_ip=dst_ip, dport=dport, src_ip=src_ip, payload=payload)
    elif ptype == "3":
        packet = craft_icmp_packet(dst_ip=dst_ip, src_ip=src_ip)
    elif ptype == "4":
        dst_mac = input("Enter Destination MAC (default: ff:ff:ff:ff:ff:ff): ").strip() or "ff:ff:ff:ff:ff:ff"
        inner = craft_icmp_packet(dst_ip=dst_ip, src_ip=src_ip)
        packet = craft_ethernet_packet(dst_mac=dst_mac, inner_packet=inner)
        use_l2 = True
    else:
        print("[-] Invalid choice.")
        return

    count_in = input("Enter transmission count (default: 1): ").strip()
    count = int(count_in) if count_in.isdigit() else 1
    preview_and_send(packet, use_layer2=use_l2, count=count)


def handle_wifi_manager():
    print(f"\n{COLORS['BOLD']}--- [ Wi-Fi Manager & Saved Password Recovery ] ---{COLORS['RESET']}")
    print("1) 📡 Scan nearby Wi-Fi networks (SSID, Signal, Security, Channel)")
    print("2) 🔑 Retrieve all saved Wi-Fi connections & passwords (Requires Root)")
    print("3) 📶 Connect to a Wi-Fi network (SSID + Password)")
    print("4) 🛡️ Password security audit & entropy evaluation")
    choice = input("Select option [1-4]: ").strip()

    if choice == "1":
        nets = scan_nearby_wifi()
        print_wifi_scan_results(nets)
    elif choice == "2":
        saved = get_saved_wifi_passwords()
        print_saved_passwords(saved)
    elif choice == "3":
        ssid = input("Enter network SSID: ").strip()
        if not ssid:
            print("[-] SSID cannot be empty.")
            return
        pwd = input("Enter password (leave empty if open network): ").strip()
        connect_to_wifi(ssid, pwd)
    elif choice == "4":
        pwd = input("Enter password to audit: ").strip()
        if pwd:
            audit_password_strength(pwd)
    else:
        print("[-] Invalid option.")


def handle_router_scanner():
    print(f"\n{COLORS['BOLD']}--- [ Router Gateway Auto-Discovery & Port Scan ] ---{COLORS['RESET']}")
    print("1) 🚀 Auto-detect current router & perform full port audit")
    print("2) 🎯 Manually enter router/gateway IP to scan")
    sub = input("Select option [1-2]: ").strip()

    if sub == "1":
        auto_audit_current_router()
    elif sub == "2":
        gw_ip = input("Enter Gateway IP (e.g., 192.168.1.1): ").strip()
        if gw_ip:
            is_up, _ = icmp_ping(gw_ip, timeout=1.5)
            print(f"[*] Gateway {gw_ip} ping status: {'UP' if is_up else 'Unresponsive'}")
            scan_router_ports(gw_ip)
    else:
        print("[-] Invalid option.")


def handle_wifi_beacon_sniffer():
    print(f"\n{COLORS['BOLD']}--- [ 802.11 Wi-Fi Beacon Security Inspector ] ---{COLORS['RESET']}")
    print("1) 📁 Analyze Wi-Fi Beacons from a saved .pcap file")
    print("2) 📡 Live capture 802.11 Beacons (Requires Monitor Mode interface)")
    sub = input("Select option [1-2]: ").strip()

    if sub == "1":
        pcap_path = input("Enter path to wireless .pcap file: ").strip()
        if pcap_path and os.path.exists(pcap_path):
            analyze_wireless_pcap(pcap_path)
        else:
            print("[-] File does not exist.")
    elif sub == "2":
        iface = input("Enter wireless monitor mode interface (e.g. wlan0mon): ").strip()
        if iface:
            count = int(input("Enter beacon count (default: 30): ").strip() or "30")
            # pyrefly: ignore [unexpected-keyword]
            live_beacon_sniff(iface=iface, count=count)
    else:
        print("[-] Invalid option.")


def handle_launch_gui():
    print(f"\n{COLORS['BOLD']}--- [ Launching Tkinter Desktop GUI ] ---{COLORS['RESET']}")
    gui_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gui.py")
    try:
        subprocess.run([sys.executable, gui_path])
    except Exception as e:
        print(f"{COLORS['RED']}[-] Failed to launch GUI: {e}{COLORS['RESET']}")


def handle_network_port_tester():
    print(f"\n{COLORS['BOLD']}--- [ Network Port Tester & Service Auditor (Multi-Host) ] ---{COLORS['RESET']}")
    run_interactive_network_tester()


def run_interactive_menu():
    """Main interactive menu dispatch loop."""
    menu = f"""
{COLORS['BOLD']}Select an operation:{COLORS['RESET']}
  {COLORS['GREEN']}1){COLORS['RESET']} 📡 Live Packet Sniffer & PCAP Exporter       (sniff, wrpcap)
  {COLORS['GREEN']}2){COLORS['RESET']} 📁 PCAP Capture Reader & Deep Dissection      (rdpcap, .show)
  {COLORS['GREEN']}3){COLORS['RESET']} 🔍 ARP Local Network Discovery Scanner       (ARP, Ether, srp)
  {COLORS['GREEN']}4){COLORS['RESET']} 🎯 ICMP Ping & TCP SYN Port Scanner          (IP, TCP, ICMP, sr1)
  {COLORS['GREEN']}5){COLORS['RESET']} 🛠️ Custom Packet Crafter & Transmitter       (IP, TCP, UDP, send, sendp)
  {COLORS['CYAN']}6){COLORS['RESET']} 📶 Wi-Fi Manager & Saved Password Recovery   (Scan, Passwords, Connect, Audit)
  {COLORS['CYAN']}7){COLORS['RESET']} 🌐 Router Gateway Auto-Discovery & Port Scan (Auto-detect router, Scan services)
  {COLORS['CYAN']}8){COLORS['RESET']} 🛡️ 802.11 Wi-Fi Beacon Security Inspector    (WPA2/WPA3 Dissection)
  {COLORS['CYAN']}9){COLORS['RESET']} 🌍 HTTP & Web Reconnaissance (Requests)       (GET, POST, Headers, APIs, Session)
  {COLORS['CYAN']}10){COLORS['RESET']} 🔐 Remote SSH & SFTP Automation (Paramiko)   (Connect, Exec, Audit, SFTP)
  {COLORS['BOLD']}{COLORS['YELLOW']}11){COLORS['RESET']} 🌐 Network Port Tester & Service Auditor     (Subnet Sweep, Multi-Host Ports & Banners)
  {COLORS['BOLD']}{COLORS['GREEN']}12){COLORS['RESET']} 🖥️ Launch Desktop GUI (Tkinter)              (Multi-tab Desktop Interface)
  {COLORS['RED']}13){COLORS['RESET']} ❌ Exit
"""
    while True:
        print(menu)
        choice = input("Enter option [1-13]: ").strip()
        if choice == "1":
            handle_sniffer()
        elif choice == "2":
            handle_pcap_analyzer()
        elif choice == "3":
            handle_arp_scanner()
        elif choice == "4":
            handle_port_scanner()
        elif choice == "5":
            handle_packet_crafter()
        elif choice == "6":
            handle_wifi_manager()
        elif choice == "7":
            handle_router_scanner()
        elif choice == "8":
            handle_wifi_beacon_sniffer()
        elif choice == "9":
            run_interactive_http_menu()
        elif choice == "10":
            run_interactive_ssh_menu()
        elif choice == "11":
            handle_network_port_tester()
        elif choice == "12":
            handle_launch_gui()
        elif choice == "13":
            print(f"\n{COLORS['CYAN']}[*] Goodbye!{COLORS['RESET']}")
            sys.exit(0)
        else:
            print(f"{COLORS['RED']}[-] Invalid option. Please select 1-13.{COLORS['RESET']}")
