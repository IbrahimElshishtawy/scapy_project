"""
CLI Banner & Terminal Typography.
"""

from core.config import COLORS


def get_banner() -> str:
    """Returns the stylized ASCII banner for Scapy Network Toolkit."""
    c_cyan = COLORS["CYAN"]
    c_bold = COLORS["BOLD"]
    c_reset = COLORS["RESET"]
    banner = f"""{c_cyan}{c_bold}
 ================================================================
       _____ _____          _______     __  _______ _  __ 
      / ____/ ____|   /\\   |  __ \\ \\   / / |__   __| |/ / 
     | (___| |       /  \\  | |__) \\ \\_/ /     | |  | ' /  
      \\___ \\ |      / /\\ \\ |  ___/ \\   /      | |  |  <   
      ____) | |____ / ____ \\| |      | |       | |  | . \\  
     |_____/ \\_____/_/    \\_\\_|      |_|       |_|  |_|\\_\\ 
                SCAPY NETWORK TOOLKIT & PACKET SUITE (v2.0)
 ================================================================
  Layer 2/3: IP(), TCP(), UDP(), ICMP(), ARP(), sr1(), send/sendp()
  Inspection: sniff(), wrpcap(), rdpcap(), .show(), 802.11 Beacons
  Recon & Remote: Requests HTTP APIs, Security Headers, Paramiko SSH
 ----------------------------------------------------------------{c_reset}"""
    return banner
