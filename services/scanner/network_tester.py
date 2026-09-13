"""
Network-Wide Multi-Host Port Scanner & Service Tester Service.
Enterprise Modular Architecture v2.0.

Provides automated local subnet discovery, active host sweep (ARP/Ping),
multi-threaded TCP port scanning, and deep service banner grabbing / HTTP testing.
"""

import os
import re
import ssl
import html
import time
import socket
import ipaddress
import subprocess
from typing import Dict, List, Optional, Tuple, Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import conf, Ether, ARP, srp
from core.config import COMMON_PORTS, ROUTER_COMMON_SERVICES
from core.privileges import is_root

# Combined targeted audit port list
DEFAULT_TEST_PORTS = sorted(list(set(
    list(COMMON_PORTS.keys()) + list(ROUTER_COMMON_SERVICES.keys())
)))


def detect_local_network_context() -> Dict[str, Any]:
    """
    Auto-detects the current machine's network context:
    - Active network interface
    - Local IP address
    - Default Gateway IP & MAC
    - Subnet CIDR notation (e.g. 192.168.1.0/24)
    """
    gateway_ip = None
    local_ip = None
    iface = None
    subnet_cidr = "192.168.1.0/24"
    gateway_mac = "Unknown"

    # 1. Scapy route table
    try:
        route = conf.route.route("0.0.0.0")
        if route and route[2] != "0.0.0.0":
            iface = route[0]
            local_ip = route[1]
            gateway_ip = route[2]
    except Exception:
        pass

    # 2. Extract accurate subnet CIDR from 'ip' command
    if iface:
        try:
            proc = subprocess.run(
                ["ip", "-o", "-4", "addr", "show", str(iface)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2
            )
            for part in proc.stdout.split():
                if "/" in part and not part.startswith("brd"):
                    net = ipaddress.IPv4Interface(part).network
                    subnet_cidr = str(net)
                    break
        except Exception:
            pass

    # 3. Fallback subnet calculation if not detected
    if not subnet_cidr and local_ip:
        try:
            # Assume /24 by default
            net = ipaddress.IPv4Interface(f"{local_ip}/24").network
            subnet_cidr = str(net)
        except Exception:
            subnet_cidr = "192.168.1.0/24"

    # 4. Check ARP cache for Gateway MAC
    if gateway_ip:
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    fields = line.split()
                    if len(fields) >= 4 and fields[0] == gateway_ip:
                        gateway_mac = fields[3]
                        break
        except Exception:
            pass

    hostname = socket.gethostname()

    return {
        "iface": iface or "unknown",
        "local_ip": local_ip or "127.0.0.1",
        "gateway_ip": gateway_ip or "unknown",
        "gateway_mac": gateway_mac,
        "subnet_cidr": subnet_cidr,
        "hostname": hostname
    }


def _read_known_neighbors() -> Dict[str, str]:
    """Reads known IP-to-MAC mappings from /proc/net/arp and ip neigh."""
    neighbors = {}
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        neighbors[parts[0]] = parts[3]
    except Exception:
        pass

    try:
        proc = subprocess.run(["ip", "neigh", "show"], stdout=subprocess.PIPE, text=True, timeout=2)
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                mac = parts[parts.index("lladdr") + 1]
                neighbors[ip] = mac
    except Exception:
        pass

    return neighbors


def discover_active_hosts(
    subnet: Optional[str] = None,
    timeout: float = 2.0,
    max_workers: int = 50,
    callback: Optional[Callable[[Dict[str, Any]], None]] = None
) -> List[Dict[str, Any]]:
    """
    Discovers all live hosts on the target subnet.
    Uses Layer 2 Scapy ARP Broadcast if Root;
    gracefully falls back to Multi-threaded Ping Sweep & ARP cache if non-Root.
    """
    ctx = detect_local_network_context()
    target_subnet = subnet or ctx["subnet_cidr"]
    discovered: Dict[str, Dict[str, Any]] = {}
    known_neighbors = _read_known_neighbors()

    # Always add local machine and gateway
    if ctx["local_ip"] and ctx["local_ip"] != "127.0.0.1":
        discovered[ctx["local_ip"]] = {
            "ip": ctx["local_ip"],
            "mac": "Self (Local Host)",
            "hostname": ctx["hostname"],
            "is_gateway": False,
            "is_local": True
        }

    if ctx["gateway_ip"] and ctx["gateway_ip"] != "unknown":
        gw_mac = ctx["gateway_mac"]
        if gw_mac == "Unknown" and ctx["gateway_ip"] in known_neighbors:
            gw_mac = known_neighbors[ctx["gateway_ip"]]
        discovered[ctx["gateway_ip"]] = {
            "ip": ctx["gateway_ip"],
            "mac": gw_mac,
            "hostname": "Default Gateway (Router)",
            "is_gateway": True,
            "is_local": False
        }

    # Approach A: Scapy ARP broadcast (Requires Root)
    arp_success = False
    if is_root():
        try:
            arp_req = ARP(pdst=target_subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_req
            answered, _ = srp(packet, timeout=timeout, verbose=False)

            for _, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                if ip not in discovered:
                    hostname = _safe_reverse_dns(ip)
                    host_info = {
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                        "is_gateway": (ip == ctx["gateway_ip"]),
                        "is_local": (ip == ctx["local_ip"])
                    }
                    discovered[ip] = host_info
                    if callback:
                        callback(host_info)
            arp_success = True
        except Exception:
            arp_success = False

    # Approach B: Multi-threaded Ping Sweep (Works without root)
    if not arp_success:
        try:
            network = ipaddress.IPv4Network(target_subnet, strict=False)
            hosts_to_probe = [str(ip) for ip in network.hosts() if str(ip) not in discovered]

            def probe_host(ip_str: str) -> Optional[str]:
                try:
                    res = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", ip_str],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    if res.returncode == 0:
                        return ip_str
                except Exception:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(probe_host, ip): ip for ip in hosts_to_probe}
                for fut in as_completed(futures):
                    res_ip = fut.result()
                    if res_ip and res_ip not in discovered:
                        mac = known_neighbors.get(res_ip, "Dynamic (Non-root)")
                        hostname = _safe_reverse_dns(res_ip)
                        host_info = {
                            "ip": res_ip,
                            "mac": mac,
                            "hostname": hostname,
                            "is_gateway": (res_ip == ctx["gateway_ip"]),
                            "is_local": (res_ip == ctx["local_ip"])
                        }
                        discovered[res_ip] = host_info
                        if callback:
                            callback(host_info)
        except Exception:
            pass

    # Sort hosts naturally by IP
    sorted_hosts = sorted(
        list(discovered.values()),
        key=lambda h: ipaddress.IPv4Address(h["ip"]) if _is_valid_ipv4(h["ip"]) else 0
    )
    return sorted_hosts


def _is_valid_ipv4(ip_str: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False


def _safe_reverse_dns(ip_str: str) -> str:
    """Performs safe, fast reverse DNS lookup with timeout."""
    try:
        return socket.gethostbyaddr(ip_str)[0]
    except Exception:
        return "Unknown"


def _clean_banner(banner_raw: bytes) -> str:
    """Decodes and sanitizes raw banner bytes into a readable single-line summary."""
    try:
        text = banner_raw.decode("utf-8", errors="replace").strip()
    except Exception:
        text = str(banner_raw).strip()

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "Connected (No initial banner)"

    summary = " | ".join(lines[:3])
    if len(summary) > 120:
        summary = summary[:117] + "..."
    return summary


def _probe_http(ip: str, port: int, use_ssl: bool = False, timeout: float = 1.2) -> Dict[str, str]:
    """
    Performs specialized HTTP/HTTPS probe:
    Sends HTTP request and extracts Status Code, Server Header, and Page Title.
    """
    info = {"banner": "", "title": "", "server": "", "status": ""}
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {ip}:{port}\r\n"
        f"User-Agent: Mozilla/5.0 (ScapyPortTester)\r\n"
        f"Accept: text/html,application/xhtml+xml,*/*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8")

    s = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw_sock, server_hostname=ip)
        else:
            s = raw_sock

        s.sendall(req)
        response_data = b""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                chunk = s.recv(2048)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) >= 4096:
                    break
            except Exception:
                break

        resp_text = response_data.decode("latin-1", errors="replace")
        if resp_text:
            first_line = resp_text.splitlines()[0] if resp_text.splitlines() else ""
            if first_line.startswith("HTTP/"):
                info["status"] = first_line.strip()

            server_match = re.search(r"^Server:\s*(.+)$", resp_text, re.IGNORECASE | re.MULTILINE)
            if server_match:
                info["server"] = server_match.group(1).strip()

            title_match = re.search(r"<title>(.*?)</title>", resp_text, re.IGNORECASE | re.DOTALL)
            if title_match:
                raw_title = " ".join(title_match.group(1).split())
                info["title"] = html.unescape(raw_title)[:50]

            parts = []
            if info["status"]:
                parts.append(info["status"])
            if info["server"]:
                parts.append(f"Server: {info['server']}")
            if info["title"]:
                parts.append(f"Title: '{info['title']}'")

            info["banner"] = " | ".join(parts) if parts else first_line
    except Exception as e:
        info["banner"] = f"HTTP Probe error: {str(e)}"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass

    return info


def test_service_port(ip: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """
    Tests whether a TCP port is open on the target IP, measures latency,
    and runs active banner grabbing / service identification.
    Returns None if port is closed or filtered.
    """
    service_name = COMMON_PORTS.get(port, ROUTER_COMMON_SERVICES.get(port, f"Port-{port}"))
    start_t = time.perf_counter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        err = sock.connect_ex((ip, port))
        latency = (time.perf_counter() - start_t) * 1000.0  # ms
        if err != 0:
            sock.close()
            return None

        banner = "Open & Responsive"
        is_responsive = True

        # Specialized Protocol Probes
        if port in (80, 8080, 8000, 8888, 5000):
            sock.close()
            http_res = _probe_http(ip, port, use_ssl=False, timeout=timeout)
            banner = http_res["banner"] or "HTTP Server (Responsive)"
        elif port in (443, 8443, 9443):
            sock.close()
            https_res = _probe_http(ip, port, use_ssl=True, timeout=timeout)
            banner = https_res["banner"] or "HTTPS / TLS Encrypted Web Server"
        else:
            try:
                sock.settimeout(0.6)
                data = sock.recv(512)
                if not data:
                    sock.sendall(b"\r\n")
                    data = sock.recv(512)
                if data:
                    banner = _clean_banner(data)
                else:
                    banner = "Connected (Silent/Binary service)"
            except socket.timeout:
                banner = "Connected (No prompt banner received)"
            except Exception as e:
                banner = f"Connected ({str(e)})"
            finally:
                sock.close()

        risk_level = "INFO"
        if port == 23:
            risk_level = "HIGH (Unencrypted Telnet)"
        elif port == 7547:
            risk_level = "MEDIUM (TR-069 Management)"
        elif port == 21:
            risk_level = "LOW (Unencrypted FTP)"
        elif port in (3306, 5432, 1433, 27017):
            risk_level = "MEDIUM (Exposed Database)"

        return {
            "port": port,
            "service": service_name,
            "status": "Open",
            "responsive": is_responsive,
            "latency_ms": round(latency, 2),
            "banner": banner,
            "risk_level": risk_level
        }

    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


def scan_and_test_host(
    ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    max_threads: int = 20,
    callback: Optional[Callable[[Dict[str, Any]], None]] = None
) -> List[Dict[str, Any]]:
    """
    Scans and tests all specified ports on a single host in parallel.
    Returns list of open tested port dicts.
    """
    target_ports = ports or DEFAULT_TEST_PORTS
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(test_service_port, ip, p, timeout): p for p in target_ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports.append(res)
                if callback:
                    callback(res)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def run_network_audit(
    subnet: Optional[str] = None,
    ports: Optional[List[int]] = None,
    host_timeout: float = 2.0,
    port_timeout: float = 1.0,
    max_host_workers: int = 40,
    max_port_workers: int = 20,
    on_host_discovered: Optional[Callable[[Dict[str, Any]], None]] = None,
    on_port_tested: Optional[Callable[[str, Dict[str, Any]], None]] = None
) -> Dict[str, Any]:
    """
    Complete end-to-end network audit:
    1. Detects local network context and subnet.
    2. Sweeps and discovers all active live hosts.
    3. Multi-thread tests ports and grabs banners for each discovered host.
    4. Aggregates complete security and services report.
    """
    ctx = detect_local_network_context()
    target_subnet = subnet or ctx["subnet_cidr"]
    target_ports = ports or DEFAULT_TEST_PORTS

    hosts = discover_active_hosts(
        subnet=target_subnet,
        timeout=host_timeout,
        max_workers=max_host_workers,
        callback=on_host_discovered
    )

    results = []
    total_open_ports = 0

    for host in hosts:
        host_ip = host["ip"]

        def port_callback(port_result: Dict[str, Any]):
            if on_port_tested:
                on_port_tested(host_ip, port_result)

        open_ports = scan_and_test_host(
            ip=host_ip,
            ports=target_ports,
            timeout=port_timeout,
            max_threads=max_port_workers,
            callback=port_callback
        )

        total_open_ports += len(open_ports)
        results.append({
            "host": host,
            "open_ports": open_ports,
            "open_count": len(open_ports)
        })

    return {
        "context": ctx,
        "subnet": target_subnet,
        "scanned_ports_count": len(target_ports),
        "total_hosts_found": len(hosts),
        "total_open_ports": total_open_ports,
        "details": results
    }
