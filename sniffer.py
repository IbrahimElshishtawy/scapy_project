# pyrefly: ignore [missing-import]
from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_callback(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"
            sport = "-"
            dport = "-"

        else:
            protocol = "Other"
            sport = "-"
            dport = "-"

        print(
            f"{source:<15} -> "
            f"{destination:<15} | "
            f"{protocol:<5} | "
            f"{sport:<6} -> {dport}"
        )


print("Starting Packet Sniffer...")
print("-" * 70)

sniff(prn=packet_callback, store=False)

