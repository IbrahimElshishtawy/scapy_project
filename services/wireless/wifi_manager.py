"""
Wi-Fi Management: Nearby SSID Scanning, Saved Passwords Recovery, Connection.
"""

import os
import glob
import subprocess
from typing import List, Dict, Tuple


def scan_nearby_wifi() -> List[Dict[str, str]]:
    """
    Scans for nearby wireless networks using nmcli tool.
    Returns list of dicts with keys: ssid, bssid, mode, chan, freq, rate, signal, bars, security.
    """
    cmd = ["nmcli", "-t", "-f", "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY", "dev", "wifi", "list", "--rescan", "yes"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=12)
        lines = proc.stdout.strip().split("\n")
        networks = []
        for line in lines:
            if not line.strip():
                continue
            parts = line.split(":")
            if len(parts) >= 9:
                ssid = parts[0] or "<Hidden SSID>"
                bssid = ":".join(parts[1:7]) if len(parts) > 9 else parts[1]
                idx = len(parts) - 7
                mode = parts[idx]
                chan = parts[idx + 1]
                freq = parts[idx + 2]
                rate = parts[idx + 3]
                signal = parts[idx + 4]
                bars = parts[idx + 5]
                security = parts[idx + 6]
                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "mode": mode,
                    "chan": chan,
                    "freq": freq,
                    "rate": rate,
                    "signal": signal,
                    "bars": bars,
                    "security": security if security else "OPEN"
                })
        return networks
    except Exception as e:
        return []


def get_saved_wifi_passwords() -> List[Dict[str, str]]:
    """
    Retrieves stored Wi-Fi profiles and passwords from NetworkManager connection files.
    Requires root/superuser access.
    """
    connections_path = "/etc/NetworkManager/system-connections/*.nmconnection"
    files = glob.glob(connections_path)
    results = []

    for filepath in files:
        ssid = None
        key_mgmt = "None"
        psk = "Not Found / Open"
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.readlines()

            for line in content:
                line = line.strip()
                if line.startswith("id="):
                    ssid = line.split("=", 1)[1]
                elif line.startswith("key-mgmt="):
                    key_mgmt = line.split("=", 1)[1]
                elif line.startswith("psk="):
                    psk = line.split("=", 1)[1]

            if ssid:
                results.append({
                    "ssid": ssid,
                    "security": key_mgmt,
                    "password": psk,
                    "profile_path": filepath
                })
        except PermissionError:
            return [{"error": "Permission Denied: Root/sudo privileges required to read NetworkManager secrets."}]
        except Exception:
            continue

    return results


def connect_to_wifi(ssid: str, password: str = "") -> Tuple[bool, str]:
    """Connects to a Wi-Fi network using nmcli."""
    if password.strip():
        cmd = ["nmcli", "dev", "wifi", "connect", ssid.strip(), "password", password.strip()]
    else:
        cmd = ["nmcli", "dev", "wifi", "connect", ssid.strip()]

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        if proc.returncode == 0:
            return True, proc.stdout.strip()
        else:
            return False, proc.stderr.strip() or proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "Connection attempt timed out."
    except Exception as e:
        return False, str(e)
