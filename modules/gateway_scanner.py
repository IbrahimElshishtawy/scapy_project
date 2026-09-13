#!/usr/bin/env python3
"""
Router Gateway Auto-Discovery & Port Scanner Module
Detects the default gateway IP of the connected network using Scapy,
then performs targeted port and service inspection to find open router services.
"""

import subprocess
from scapy.all import conf, IP, TCP, sr1, send
from modules.port_scanner import icmp_ping

ROUTER_COMMON_SERVICES = {
    21: ("FTP", "Router File Transfer / Firmware update"),
    22: ("SSH", "Secure Remote Management console"),
    23: ("Telnet", "Unencrypted Remote Management console (Insecure!)"),
    53: ("DNS", "Router Domain Name Service cache/resolver"),
    80: ("HTTP", "Router Web Admin GUI (Standard)"),
    443: ("HTTPS", "Router Secure Web Admin GUI (SSL/TLS)"),
    139: ("NetBIOS", "Windows File Sharing / Router USB storage"),
    445: ("SMB", "Samba / Network File Sharing"),
    1900: ("UPnP", "Universal Plug and Play (Auto Port Mapping)"),
    5000: ("UPnP/Web", "Alternate Web / Media Server"),
    7547: ("TR-069", "CWMP Remote Management (Used by ISPs)"),
    8080: ("HTTP-Alt", "Alternate Router Web Admin Port"),
    8443: ("HTTPS-Alt", "Alternate Router Secure Web Port")
}


def get_default_gateway():
    """
    Automatically detects the default gateway IP, local IP, and interface name.
    Uses Scapy routing table with fallback to system routes.
    """
    try:
        iface, local_ip, gateway_ip = conf.route.route("0.0.0.0")
        if gateway_ip and gateway_ip != "0.0.0.0":
            return {
                "gateway_ip": gateway_ip,
                "local_ip": local_ip,
                "interface": iface
            }
    except Exception:
        pass

    # Fallback to ip route
    try:
        proc = subprocess.run(["ip", "route", "show", "default"], stdout=subprocess.PIPE, text=True)
        line = proc.stdout.strip()
        parts = line.split()
        if "via" in parts:
            idx = parts.index("via")
            gw = parts[idx + 1]
            dev = parts[parts.index("dev") + 1] if "dev" in parts else "unknown"
            return {
                "gateway_ip": gw,
                "local_ip": "unknown",
                "interface": dev
            }
    except Exception:
        pass

    return None


def scan_router_ports(gateway_ip: str, custom_ports: list = None, timeout: float = 1.0):
    """
    Performs a TCP SYN scan on the router's gateway IP and highlights active services.
    """
    ports_to_scan = custom_ports if custom_ports else list(ROUTER_COMMON_SERVICES.keys())

    print("\n" + "=" * 80)
    print(f"[*] Scanning Router Gateway: {gateway_ip}")
    print("=" * 80)
    print(f"{'Port':<8} | {'Status':<12} | {'Service':<12} | {'Description / Security Notes'}")
    print("-" * 80)

    results = []
    for port in sorted(ports_to_scan):
        syn_pkt = IP(dst=gateway_ip) / TCP(dport=port, flags="S")
        reply = sr1(syn_pkt, timeout=timeout, verbose=False)

        service_name, desc = ROUTER_COMMON_SERVICES.get(port, ("Custom", "User defined port"))
        status = "Closed"

        if reply is None:
            status = "Filtered"
        elif reply.haslayer(TCP):
            flags = reply[TCP].flags
            if flags == 0x12 or flags == "SA":
                status = "Open"
                # Tear down connection cleanly with RST
                rst = IP(dst=gateway_ip) / TCP(dport=port, flags="R")
                send(rst, verbose=False)
            elif flags == 0x14 or flags == "RA" or "R" in str(flags):
                status = "Closed"

        results.append((port, status, service_name, desc))

        # Pretty print line
        if status == "Open":
            color_status = f"\033[92m{status:<12}\033[0m"
            print(f"{port:<8} | {color_status} | \033[1m{service_name:<12}\033[0m | {desc}")
        elif status == "Filtered":
            color_status = f"\033[93m{status:<12}\033[0m"
            print(f"{port:<8} | {color_status} | {service_name:<12} | {desc}")
        else:
            color_status = f"\033[90m{status:<12}\033[0m"
            print(f"{port:<8} | {color_status} | {service_name:<12} | {desc}")

    print("=" * 80)
    open_ports = [r for r in results if r[1] == "Open"]
    print(f"[+] Scan Complete: Found {len(open_ports)} open port(s) on the router.")

    # Highlights
    if any(p[0] in [80, 443, 8080, 8443] for p in open_ports):
        print("💡 \033[96mWeb Administration is available! You can access the router via browser.\033[0m")
    if any(p[0] == 23 for p in open_ports):
        print("⚠️  \033[91mWarning: Telnet (Port 23) is open. This service transmits passwords in cleartext!\033[0m")
    if any(p[0] == 7547 for p in open_ports):
        print("ℹ️  TR-069 is open (Used by your Internet Service Provider for remote provisioning).")
    print("=" * 80 + "\n")

    return results


def auto_audit_current_router():
    """
    Discovers the current default gateway and runs an audit scan.
    """
    gw_info = get_default_gateway()
    if not gw_info:
        print("[-] Could not automatically detect Default Gateway. Ensure you are connected to a network.")
        return None

    gw_ip = gw_info["gateway_ip"]
    print(f"\n[+] Detected Default Gateway (Router) : \033[92m{gw_ip}\033[0m")
    print(f"    Local Assigned IP                 : {gw_info['local_ip']}")
    print(f"    Active Interface                  : {gw_info['interface']}")

    print(f"\n[*] Testing router reachability (Ping)...")
    is_up, _ = icmp_ping(gw_ip, timeout=1.5)
    if is_up:
        print(f"\033[92m[+] Router {gw_ip} is UP and responding to Ping!\033[0m")
    else:
        print(f"\033[93m[!] Router did not respond to ICMP Ping (it may have ICMP Echo disabled).\033[0m")

    return scan_router_ports(gw_ip)


if __name__ == "__main__":
    auto_audit_current_router()
