#!/usr/bin/env python3
"""
Wi-Fi 802.11 Beacon & Security Inspector Module
Uses Scapy's Dot11, Dot11Beacon, and Dot11Elt layers to dissect Wi-Fi management frames,
extract SSIDs, BSSIDs, Channels, and analyze encryption types (Open, WEP, WPA, WPA2, WPA3).
"""

from scapy.all import sniff, rdpcap, Dot11, Dot11Beacon, Dot11Elt


def analyze_beacon_packet(packet):
    """
    Dissects a single 802.11 Beacon or Probe Response frame and determines:
    SSID, BSSID, Channel, and Encryption Security Profile.
    """
    if not packet.haslayer(Dot11Beacon):
        return None

    bssid = packet[Dot11].addr2 or packet[Dot11].addr3
    ssid = "<Hidden SSID>"
    channel = "-"
    capabilities = packet.sprintf("%Dot11Beacon.cap%")
    has_privacy = "privacy" in capabilities.lower()

    is_wpa = False
    is_wpa2 = False
    is_wpa3 = False
    is_enterprise = False

    elt = packet.getlayer(Dot11Elt)
    while elt:
        # ID 0: SSID
        if elt.ID == 0:
            try:
                raw_info = elt.info.decode("utf-8", errors="ignore")
                if raw_info:
                    ssid = raw_info
            except Exception:
                pass

        # ID 3: DS Parameter Set (Channel)
        elif elt.ID == 3 and elt.info:
            channel = str(elt.info[0])

        # ID 48: RSN Information (WPA2 / WPA3)
        elif elt.ID == 48:
            is_wpa2 = True
            raw_rsn = elt.info
            # Check for WPA3 SAE (Auth suite 8: 00-0F-AC:8)
            if b"\x00\x0f\xac\x08" in raw_rsn:
                is_wpa3 = True
            # Check for 802.1X Enterprise (Auth suite 1: 00-0F-AC:1)
            if b"\x00\x0f\xac\x01" in raw_rsn:
                is_enterprise = True

        # ID 221: Vendor Specific (WPA1 OUI: 00:50:f2:01)
        elif elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x01"):
            is_wpa = True

        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    # Determine security rating
    if is_wpa3:
        sec = "WPA3-SAE (Modern & Highly Secure)"
    elif is_wpa2 and is_enterprise:
        sec = "WPA2-Enterprise (802.1X)"
    elif is_wpa2 and is_wpa:
        sec = "WPA/WPA2-Personal Mixed"
    elif is_wpa2:
        sec = "WPA2-PSK (AES/CCMP)"
    elif is_wpa:
        sec = "WPA-Personal (Legacy)"
    elif has_privacy:
        sec = "WEP (Broken & Insecure!)"
    else:
        sec = "Open / None (Unencrypted)"

    return {
        "ssid": ssid,
        "bssid": bssid,
        "channel": channel,
        "security": sec,
        "raw_packet": packet
    }


def analyze_wireless_pcap(filepath: str):
    """
    Reads a .pcap file containing 802.11 frames and extracts all beacon security profiles.
    """
    packets = rdpcap(filepath)
    discovered = {}

    for pkt in packets:
        info = analyze_beacon_packet(pkt)
        if info:
            bssid = info["bssid"]
            if bssid not in discovered:
                discovered[bssid] = info

    print("\n" + "=" * 80)
    print(f"[*] Wireless PCAP Security Inspection: {filepath}")
    print(f"    Discovered {len(discovered)} unique Access Point(s)")
    print("=" * 80)
    print(f"{'BSSID (MAC)':<18} | {'Channel':<7} | {'Security':<26} | {'SSID'}")
    print("-" * 80)

    for bssid, data in discovered.items():
        print(f"{bssid:<18} | {data['channel']:<7} | {data['security']:<26} | {data['ssid']}")

    print("=" * 80 + "\n")
    return list(discovered.values())


def live_beacon_sniff(interface: str = None, count: int = 30, timeout: int = 15):
    """
    Sniffs live 802.11 Beacon management frames (requires monitor mode interface).
    """
    discovered = {}
    print("\n" + "=" * 80)
    print(f"[*] Starting 802.11 Beacon Sniff on {interface or 'default'}")
    print("    (Note: Capturing raw 802.11 frames requires a Wi-Fi card supporting Monitor Mode)")
    print("=" * 80)

    def packet_callback(pkt):
        info = analyze_beacon_packet(pkt)
        if info:
            bssid = info["bssid"]
            if bssid not in discovered:
                discovered[bssid] = info
                print(f"[+] AP Detected: {bssid} | Ch:{info['channel']} | {info['security']} | '{info['ssid']}'")

    try:
        kwargs = {
            "prn": packet_callback,
            "filter": "type mgt subtype beacon",
            "count": count,
            "timeout": timeout,
            "store": False
        }
        if interface:
            kwargs["iface"] = interface

        sniff(**kwargs)
    except Exception as e:
        print(f"[-] Live beacon sniff notice: {e}")
        print("    If your interface is not in monitor mode, use Option 1 (System Wi-Fi Scanner) or inspect a saved wireless .pcap file.")

    return list(discovered.values())


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_wireless_pcap(sys.argv[1])
    else:
        live_beacon_sniff()
