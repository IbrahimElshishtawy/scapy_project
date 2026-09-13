#!/usr/bin/env python3
"""
Scapy Network Toolkit - Interactive CLI
Comprehensive network utility covering Scapy's core capabilities:
IP, TCP, UDP, ICMP, ARP, sr/sr1, send/sendp, sniff, .show(), wrpcap/rdpcap,
plus Wi-Fi Management, Saved Password Recovery, and Router Gateway Port Scanning.
"""

import os
import sys
from datetime import datetime

# Ensure modules directory is discoverable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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

# Terminal colors
CLR_CYAN = "\033[96m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_RED = "\033[91m"
CLR_BOLD = "\033[1m"
CLR_RESET = "\033[0m"


def check_privileges():
    """Checks whether the script is executed with root/sudo privileges."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"{CLR_YELLOW}[!] Warning: You are not running as root/superuser.{CLR_RESET}")
        print(f"{CLR_YELLOW}    Packet sniffing, raw socket creation, and retrieving saved Wi-Fi secrets require root.{CLR_RESET}")
        print(f"{CLR_YELLOW}    Run with: {CLR_BOLD}sudo ./venv/bin/python main.py{CLR_RESET}\n")


def print_banner():
    banner = f"""{CLR_CYAN}{CLR_BOLD}
 ================================================================
       _____ _____          _______     __  _______ _  __ 
      / ____/ ____|   /\\   |  __ \\ \\   / / |__   __| |/ / 
     | (___| |       /  \\  | |__) \\ \\_/ /     | |  | ' /  
      \\___ \\ |      / /\\ \\ |  ___/ \\   /      | |  |  <   
      ____) | |____ / ____ \\| |      | |       | |  | . \\  
     |_____/ \\_____/_/    \\_\\_|      |_|       |_|  |_|\\_\\ 
                NETWORK TOOLKIT & PACKET SUITE
 ================================================================{CLR_RESET}
  Features: IP(), TCP(), UDP(), ICMP(), ARP(), sr1(), send/sendp(),
            sniff(), .show(), wrpcap(), rdpcap(), Wi-Fi & Gateway Scan
 ----------------------------------------------------------------"""
    print(banner)


def handle_sniffer():
    print(f"\n{CLR_BOLD}--- [ Live Packet Sniffer (sniff & wrpcap) ] ---{CLR_RESET}")
    filter_expr = input("Enter BPF filter (e.g., 'tcp', 'icmp', 'port 80', or press Enter for all): ").strip()
    count_in = input("Enter packet count (0 for continuous capture until Ctrl+C): ").strip()
    count = int(count_in) if count_in.isdigit() else 0
    show_details = input("Display full deep inspection (.show()) for every packet? (y/N): ").strip().lower() == 'y'
    save_pcap = input("Save captured packets to .pcap file? (Y/n): ").strip().lower() != 'n'

    output_pcap = None
    if save_pcap:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"captures/sniff_{timestamp}.pcap"
        chosen_path = input(f"Enter file path (default: {default_filename}): ").strip()
        output_pcap = chosen_path if chosen_path else default_filename

    start_sniffer(
        filter_expr=filter_expr,
        count=count,
        show_details=show_details,
        output_pcap=output_pcap
    )


def handle_pcap_analyzer():
    print(f"\n{CLR_BOLD}--- [ PCAP File Reader & Inspector (rdpcap & .show) ] ---{CLR_RESET}")
    filepath = input("Enter path to .pcap file (e.g., captures/sample_test.pcap): ").strip()
    packets = load_pcap(filepath)
    if not packets:
        return

    print_pcap_statistics(packets)
    list_packets_summary(packets, limit=15)

    while True:
        choice = input("Enter packet number to inspect with .show() (or 'q' to back): ").strip()
        if choice.lower() == 'q':
            break
        if choice.isdigit():
            inspect_packet(packets, int(choice))


def handle_arp_scanner():
    print(f"\n{CLR_BOLD}--- [ ARP Network Scanner (ARP, Ether, srp) ] ---{CLR_RESET}")
    ip_range = input("Enter IP range or CIDR (e.g., 192.168.1.0/24): ").strip()
    if not ip_range:
        ip_range = "192.168.1.0/24"
    results = scan_network(ip_range)
    print_results(results)


def handle_port_scanner():
    print(f"\n{CLR_BOLD}--- [ Host Ping & TCP Port Scanner (IP, TCP, ICMP, sr1) ] ---{CLR_RESET}")
    target = input("Enter target IP address (e.g. 127.0.0.1 or 8.8.8.8): ").strip()
    if not target:
        print("[-] Target IP is required.")
        return

    print(f"\n[*] Pinging {target} using ICMP Echo Request (sr1) ...")
    is_up, resp = icmp_ping(target, timeout=2)
    if is_up:
        print(f"{CLR_GREEN}[+] Host is UP and responsive!{CLR_RESET}")
        if resp:
            inspect = input("View ICMP response packet details (.show())? (y/N): ").strip().lower() == 'y'
            if inspect:
                resp.show()
    else:
        print(f"{CLR_YELLOW}[!] Host did not respond to ICMP ping (might be down or blocking ICMP).{CLR_RESET}")

    scan_choice = input("\nDo you want to perform a TCP SYN Port Scan? (Y/n): ").strip().lower() != 'n'
    if scan_choice:
        custom = input("Enter comma-separated ports to scan (press Enter for common ports): ").strip()
        if custom:
            try:
                ports = [int(p.strip()) for p in custom.split(",") if p.strip()]
            except ValueError:
                print("[-] Invalid port list format, using common ports.")
                ports = None
        else:
            ports = None
        scan_ports(target, ports=ports)


def handle_packet_crafter():
    print(f"\n{CLR_BOLD}--- [ Custom Packet Crafter & Sender (IP, TCP, UDP, ICMP, send/sendp) ] ---{CLR_RESET}")
    print("1) Craft IP / TCP Packet (SYN, HTTP, Custom Flags)")
    print("2) Craft IP / UDP Packet (Custom Payload)")
    print("3) Craft IP / ICMP Echo Packet")
    print("4) Craft Layer 2 Ethernet Frame (Ether + IP + TCP)")
    choice = input("Select packet type [1-4]: ").strip()

    dst_ip = input("Enter Destination IP (e.g., 127.0.0.1): ").strip() or "127.0.0.1"
    src_ip = input("Enter Source IP (press Enter for default local IP, or type IP to spoof): ").strip() or None

    packet = None
    use_l2 = False

    if choice == "1":
        dport_in = input("Enter Destination Port (default: 80): ").strip()
        dport = int(dport_in) if dport_in.isdigit() else 80
        sport_in = input("Enter Source Port (default: 12345): ").strip()
        sport = int(sport_in) if sport_in.isdigit() else 12345
        flags = input("Enter TCP Flags [S=SYN, A=ACK, F=FIN, P=PSH, R=RST] (default: S): ").strip().upper() or "S"
        payload = input("Enter Payload data (press Enter for none): ").strip()
        packet = craft_ip_tcp_packet(dst_ip=dst_ip, dport=dport, src_ip=src_ip, sport=sport, flags=flags, payload=payload)

    elif choice == "2":
        dport_in = input("Enter Destination Port (default: 53): ").strip()
        dport = int(dport_in) if dport_in.isdigit() else 53
        payload = input("Enter UDP Payload (default: 'Hello Scapy'): ").strip() or "Hello Scapy"
        packet = craft_ip_udp_packet(dst_ip=dst_ip, dport=dport, src_ip=src_ip, payload=payload)

    elif choice == "3":
        packet = craft_icmp_packet(dst_ip=dst_ip, src_ip=src_ip)

    elif choice == "4":
        use_l2 = True
        dst_mac = input("Enter Destination MAC (default: ff:ff:ff:ff:ff:ff): ").strip() or "ff:ff:ff:ff:ff:ff"
        inner_l3 = craft_ip_tcp_packet(dst_ip=dst_ip, src_ip=src_ip, dport=80, flags="S")
        packet = craft_ethernet_packet(dst_mac=dst_mac, inner_packet=inner_l3)

    else:
        print("[-] Invalid selection.")
        return

    count_in = input("How many times to send this packet? (default: 1): ").strip()
    count = int(count_in) if count_in.isdigit() else 1

    preview_and_send(packet, use_layer2=use_l2, count=count)


def handle_wifi_manager():
    print(f"\n{CLR_BOLD}--- [ Wi-Fi Manager & Saved Password Recovery ] ---{CLR_RESET}")
    print("1) Scan Nearby Available Wi-Fi Networks (SSID, Signal, Security)")
    print("2) View All Saved Wi-Fi Connections & Stored Passwords")
    print("3) Connect to a Wi-Fi Network")
    print("4) Audit Password Strength / Dictionary Check")
    choice = input("Select an option [1-4]: ").strip()

    if choice == "1":
        nets = scan_nearby_wifi()
        print_wifi_scan_results(nets)

    elif choice == "2":
        saved = get_saved_wifi_passwords()
        print_saved_passwords(saved)

    elif choice == "3":
        ssid = input("Enter Wi-Fi SSID to connect to: ").strip()
        if not ssid:
            print("[-] SSID is required.")
            return
        pwd = input("Enter Wi-Fi Password (leave empty if open network): ").strip()
        success = connect_to_wifi(ssid, pwd)
        if success:
            audit = input("Do you want to scan open ports on the new network's router now? (Y/n): ").strip().lower() != 'n'
            if audit:
                auto_audit_current_router()

    elif choice == "4":
        pwd = input("Enter password to test/audit: ").strip()
        if pwd:
            audit_password_strength(pwd)
        else:
            print("[-] Password cannot be empty.")
    else:
        print("[-] Invalid option.")


def handle_router_scanner():
    print(f"\n{CLR_BOLD}--- [ Router Gateway Auto-Discovery & Port Scanner ] ---{CLR_RESET}")
    print("1) Automatically Detect Current Router and Scan its Ports")
    print("2) Scan a Specific Router / Gateway IP Manually")
    choice = input("Select an option [1-2]: ").strip()

    if choice == "1":
        auto_audit_current_router()
    elif choice == "2":
        target = input("Enter Router IP (e.g. 192.168.1.1): ").strip()
        if target:
            scan_router_ports(target)
        else:
            print("[-] IP address is required.")
    else:
        print("[-] Invalid option.")


def handle_wifi_beacon_sniffer():
    print(f"\n{CLR_BOLD}--- [ 802.11 Wi-Fi Beacon Security Inspector ] ---{CLR_RESET}")
    print("1) Inspect Wireless .pcap Capture File (Dissect SSIDs & WPA2/WPA3)")
    print("2) Live Beacon Sniff (Requires Monitor Mode Interface)")
    choice = input("Select an option [1-2]: ").strip()

    if choice == "1":
        filepath = input("Enter path to wireless .pcap file: ").strip()
        if filepath and os.path.exists(filepath):
            analyze_wireless_pcap(filepath)
        else:
            print("[-] File not found.")
    elif choice == "2":
        iface = input("Enter monitor mode interface name (leave empty for default): ").strip() or None
        live_beacon_sniff(interface=iface)
    else:
        print("[-] Invalid option.")


def main():
    check_privileges()
    print_banner()

    menu = f"""
{CLR_BOLD}Select an operation:{CLR_RESET}
  {CLR_GREEN}1){CLR_RESET} 📡 Live Packet Sniffer & PCAP Exporter       (sniff, wrpcap)
  {CLR_GREEN}2){CLR_RESET} 📁 PCAP Capture Reader & Deep Dissection      (rdpcap, .show)
  {CLR_GREEN}3){CLR_RESET} 🔍 ARP Local Network Discovery Scanner       (ARP, Ether, srp)
  {CLR_GREEN}4){CLR_RESET} 🎯 ICMP Ping & TCP SYN Port Scanner          (IP, TCP, ICMP, sr1)
  {CLR_GREEN}5){CLR_RESET} 🛠️ Custom Packet Crafter & Transmitter       (IP, TCP, UDP, send, sendp)
  {CLR_CYAN}6){CLR_RESET} 📶 Wi-Fi Manager & Saved Password Recovery   (Scan, Passwords, Connect, Audit)
  {CLR_CYAN}7){CLR_RESET} 🌐 Router Gateway Auto-Discovery & Port Scan (Auto-detect router, Scan services)
  {CLR_CYAN}8){CLR_RESET} 🛡️ 802.11 Wi-Fi Beacon Security Inspector    (WPA2/WPA3 Dissection)
  {CLR_CYAN}9){CLR_RESET} 🌍 HTTP & Web Reconnaissance (Requests)       (GET, POST, Headers, APIs, Session)
  {CLR_RED}10){CLR_RESET} ❌ Exit
"""
    while True:
        print(menu)
        choice = input("Enter option [1-10]: ").strip()
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
            print(f"\n{CLR_CYAN}[*] Goodbye!{CLR_RESET}")
            sys.exit(0)
        else:
            print(f"{CLR_RED}[-] Invalid option. Please select 1-10.{CLR_RESET}")


if __name__ == "__main__":
    main()
