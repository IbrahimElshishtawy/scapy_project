"""
802.11 Wi-Fi Beacon Frame Dissector & Security Analyzer.
"""

from typing import Dict, Any, List, Optional
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, rdpcap


def analyze_beacon_packet(packet) -> Optional[Dict[str, Any]]:
    """
    Parses an 802.11 Beacon management frame to determine SSID, BSSID, channel, and encryption.
    """
    if not (packet.haslayer(Dot11) and packet.haslayer(Dot11Beacon)):
        return None

    dot11 = packet[Dot11]
    bssid = dot11.addr2 or dot11.addr3 or "Unknown"

    ssid = "<Hidden>"
    channel = "Unknown"
    has_wep = False
    has_wpa = False
    has_rsn_wpa2 = False
    has_wpa3 = False

    # Check capability flags for privacy (WEP bit)
    capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
    if "privacy" in capability:
        has_wep = True

    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:  # SSID parameter
            try:
                decoded = elt.info.decode("utf-8", errors="ignore").strip()
                if decoded:
                    ssid = decoded
            except Exception:
                pass
        elif elt.ID == 3:  # DS Parameter set (Channel)
            if elt.info:
                channel = str(ord(elt.info[:1]))
        elif elt.ID == 48:  # RSN Information (WPA2 / WPA3)
            has_rsn_wpa2 = True
            info_hex = elt.info.hex() if hasattr(elt.info, "hex") else str(elt.info)
            if "000fac08" in info_hex:  # SAE AKM suite (WPA3-Personal)
                has_wpa3 = True
        elif elt.ID == 221:  # Vendor specific (WPA1 IE)
            if elt.info and elt.info.startswith(b"\x00P\xf2\x01"):
                has_wpa = True

        elt = elt.payload.getlayer(Dot11Elt)

    # Determine encryption string
    if has_wpa3:
        encryption = "WPA3-SAE (Modern Secure)"
    elif has_rsn_wpa2:
        encryption = "WPA2-PSK (AES/CCMP)"
    elif has_wpa:
        encryption = "WPA-PSK (TKIP - Deprecated)"
    elif has_wep:
        encryption = "WEP (Vulnerable / Insecure)"
    else:
        encryption = "OPEN (No Encryption - Insecure)"

    return {
        "ssid": ssid,
        "bssid": bssid,
        "channel": channel,
        "encryption": encryption,
        "is_secure": "WPA2" in encryption or "WPA3" in encryption,
    }


def analyze_wireless_pcap(filepath: str) -> List[Dict[str, Any]]:
    """Analyzes a .pcap file for 802.11 beacon frames and returns unique networks found."""
    packets = rdpcap(filepath)
    seen_bssids = set()
    beacons = []

    for pkt in packets:
        parsed = analyze_beacon_packet(pkt)
        if parsed and parsed["bssid"] not in seen_bssids:
            seen_bssids.add(parsed["bssid"])
            beacons.append(parsed)

    return beacons
