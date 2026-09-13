#!/usr/bin/env python3
"""
Wi-Fi Manager Module
Handles:
1. Scanning nearby Wi-Fi networks (SSID, BSSID, Signal, Security, Channel)
2. Retrieving saved Wi-Fi connections and their passwords
3. Connecting to a Wi-Fi network with credentials
4. Password strength and dictionary audit
"""

import os
import re
import math
import subprocess

COMMON_WEAK_PASSWORDS = [
    "12345678", "password", "123456789", "1234567890", "1234567", "11111111",
    "00000000", "admin123", "admin", "welcome", "qwertyuiop", "qwerty",
    "password123", "pass1234", "12341234", "internet", "wifi1234", "vodafone",
    "we123456", "orange123", "etisalat", "abc12345", "iloveyou"
]


def scan_nearby_wifi():
    """
    Scans nearby Wi-Fi networks using nmcli.
    Returns a list of dictionaries with network details.
    """
    cmd = ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN,IN-USE", "dev", "wifi", "list", "--rescan", "yes"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        lines = proc.stdout.strip().split("\n")
        networks = []
        seen = set()

        for line in lines:
            if not line:
                continue
            parts = line.split(":")
            # Note: BSSID contains colons, so reconstruct correctly
            if len(parts) >= 6:
                ssid = parts[0].strip() or "<Hidden SSID>"
                bssid = ":".join(parts[1:7]).replace(r"\:", ":")
                signal = parts[7].strip() if len(parts) > 7 else "0"
                security = parts[8].strip() if len(parts) > 8 else "Open"
                channel = parts[9].strip() if len(parts) > 9 else "-"
                in_use = parts[10].strip() == "*" if len(parts) > 10 else False

                key = (ssid, bssid)
                if key not in seen:
                    seen.add(key)
                    networks.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "signal": int(signal) if signal.isdigit() else 0,
                        "security": security if security else "Open",
                        "channel": channel,
                        "connected": in_use
                    })

        networks.sort(key=lambda x: x["signal"], reverse=True)
        return networks
    except Exception as e:
        print(f"[-] Error scanning Wi-Fi: {e}")
        return []


def print_wifi_scan_results(networks: list):
    """Prints nearby networks in a clean table with signal bars."""
    print("\n" + "=" * 80)
    print(f"{'#':<3} | {'SSID':<25} | {'Signal':<10} | {'Security':<18} | {'Channel':<7} | {'Status'}")
    print("=" * 80)

    if not networks:
        print("No Wi-Fi networks detected. Ensure your Wi-Fi interface is turned on.")
    else:
        for idx, net in enumerate(networks):
            sig = net["signal"]
            # Signal bar visualization
            if sig >= 75:
                bars = "▂▄▆█ 4/4"
            elif sig >= 50:
                bars = "▂▄▆_ 3/4"
            elif sig >= 25:
                bars = "▂▄__ 2/4"
            else:
                bars = "▂___ 1/4"

            status = "\033[92mConnected (*)\033[0m" if net["connected"] else ""
            print(f"{idx+1:<3} | {net['ssid'][:25]:<25} | {bars:<10} ({sig:>2}%) | {net['security']:<18} | {net['channel']:<7} | {status}")

    print("=" * 80 + "\n")


def get_saved_wifi_passwords():
    """
    Retrieves all saved Wi-Fi connections and their passwords stored on the system.
    Requires root/sudo privileges to read stored PSK secrets.
    """
    # 1. Get all saved Wi-Fi profiles
    cmd_profiles = ["nmcli", "-t", "-f", "NAME,TYPE,UUID", "connection", "show"]
    saved_list = []

    try:
        proc = subprocess.run(cmd_profiles, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        for line in proc.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":")
            if len(parts) >= 2 and ("802-11-wireless" in parts[1] or "wifi" in parts[1]):
                name = parts[0]
                uuid = parts[2] if len(parts) > 2 else ""

                # 2. Extract stored password using nmcli show-secrets
                cmd_sec = ["nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", name]
                sec_proc = subprocess.run(cmd_sec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                password = sec_proc.stdout.strip()

                # Fallback to reading NetworkManager system-connections if empty and running as root
                if not password and os.path.exists("/etc/NetworkManager/system-connections"):
                    for filename in os.listdir("/etc/NetworkManager/system-connections"):
                        if filename.startswith(name) or name in filename:
                            try:
                                with open(os.path.join("/etc/NetworkManager/system-connections", filename), "r") as f:
                                    content = f.read()
                                    match = re.search(r"^psk=(.*)$", content, re.MULTILINE)
                                    if match:
                                        password = match.group(1).strip()
                                        break
                            except Exception:
                                pass

                saved_list.append({
                    "name": name,
                    "password": password if password else "<No Password / Open / Permission Required>"
                })

        return saved_list
    except Exception as e:
        print(f"[-] Error retrieving saved passwords: {e}")
        return []


def print_saved_passwords(saved_connections: list):
    """Displays saved Wi-Fi profiles and their passwords."""
    print("\n" + "=" * 65)
    print("             SAVED WI-FI CONNECTIONS & PASSWORDS")
    print("=" * 65)
    print(f"{'#':<3} | {'Wi-Fi SSID / Profile Name':<30} | {'Password'}")
    print("-" * 65)

    if not saved_connections:
        print("No saved Wi-Fi connections found or permission denied.")
    else:
        for idx, item in enumerate(saved_connections):
            pwd = item['password']
            if pwd.startswith("<"):
                print(f"{idx+1:<3} | {item['name']:<30} | \033[90m{pwd}\033[0m")
            else:
                print(f"{idx+1:<3} | {item['name']:<30} | \033[92m{pwd}\033[0m")

    print("=" * 65 + "\n")


def connect_to_wifi(ssid: str, password: str = "", timeout: int = 15):
    """
    Connects to a Wi-Fi network using nmcli.
    """
    print(f"\n[*] Connecting to Wi-Fi network: '{ssid}' ...")
    cmd = ["nmcli", "dev", "wifi", "connect", ssid]
    if password:
        cmd.extend(["password", password])

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if proc.returncode == 0:
            print(f"\033[92m[+] Successfully connected to '{ssid}'!\033[0m")

            # Check assigned IP
            ip_cmd = ["ip", "-4", "addr", "show"]
            ip_proc = subprocess.run(ip_cmd, stdout=subprocess.PIPE, text=True)
            print("[+] Network Interface Status:")
            for line in ip_proc.stdout.splitlines():
                if "inet " in line and "127.0.0.1" not in line:
                    print(f"    {line.strip()}")
            return True
        else:
            print(f"\033[91m[-] Connection failed:\033[0m {proc.stderr.strip() or proc.stdout.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print(f"[-] Connection attempt timed out after {timeout} seconds.")
        return False
    except Exception as e:
        print(f"[-] Connection error: {e}")
        return False


def calculate_entropy(password: str) -> float:
    """Calculates the Shannon entropy of a password string."""
    if not password:
        return 0.0
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32

    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def audit_password_strength(password: str, custom_wordlist: str = None):
    """
    Evaluates password security against dictionary lists and complexity metrics.
    """
    print("\n" + "=" * 60)
    print(f"[*] Password Security Audit for: '{password}'")
    print("=" * 60)

    # 1. Length check
    length = len(password)
    print(f"  - Length           : {length} characters")

    # 2. Character diversity
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digits = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    types_count = sum([has_lower, has_upper, has_digits, has_special])
    print(f"  - Character Sets   : {types_count}/4 (Lowercase, Uppercase, Numbers, Symbols)")

    # 3. Entropy
    entropy = calculate_entropy(password)
    print(f"  - Shannon Entropy  : {entropy:.1f} bits")

    # 4. Dictionary Check
    is_common = password.lower() in [p.lower() for p in COMMON_WEAK_PASSWORDS]
    if not is_common and custom_wordlist and os.path.exists(custom_wordlist):
        with open(custom_wordlist, "r", errors="ignore") as f:
            for line in f:
                if line.strip().lower() == password.lower():
                    is_common = True
                    break

    print(f"  - Dictionary Check : {'FAILED (Matches common password dictionary!)' if is_common else 'PASSED (Not in common dictionaries)'}")

    # 5. Overall verdict
    print("-" * 60)
    if is_common or length < 8 or entropy < 30:
        grade = "\033[91mVERY WEAK / VULNERABLE\033[0m"
        recommendation = "Change password immediately. Use at least 12+ characters with mixed case, numbers, and symbols."
    elif length < 10 or entropy < 50 or types_count < 3:
        grade = "\033[93mMEDERATE\033[0m"
        recommendation = "Consider adding special characters and increasing length to 12+."
    elif entropy < 70:
        grade = "\033[92mSTRONG\033[0m"
        recommendation = "Good password security. Resistant to standard brute-force attacks."
    else:
        grade = "\033[96mVERY STRONG / EXCELLENT\033[0m"
        recommendation = "High entropy and complex structure. Highly secure."

    print(f"  Verdict: {grade}")
    print(f"  Recommendation: {recommendation}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    nets = scan_nearby_wifi()
    print_wifi_scan_results(nets)
    saved = get_saved_wifi_passwords()
    print_saved_passwords(saved)
