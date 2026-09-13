"""
Tab 5: Custom Packet Crafter & Transmitter.
"""

import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from gui.tabs.base_tab import BaseTab
from services.packet.crafter_service import (
    craft_tcp_packet,
    craft_udp_packet,
    craft_icmp_packet,
    craft_ethernet_packet,
    send_crafted_packet,
)
from services.packet.pcap_service import dissect_packet_details


class CrafterTab(BaseTab):
    """Custom packet forgery and transmission tab."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.current_packet = None
        self.build_ui()

    def build_ui(self):
        form = tk.Frame(self, bg=self.theme["bg_card"])
        form.pack(fill="x", padx=10, pady=10)

        # Protocol Choice
        tk.Label(form, text="Layer 4 Protocol:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=0, column=0, sticky="w", padx=5, pady=4)
        self.var_proto = tk.StringVar(value="TCP")
        proto_frame = tk.Frame(form, bg=self.theme["bg_card"])
        proto_frame.grid(row=0, column=1, columnspan=3, sticky="w")
        for p in ["TCP", "UDP", "ICMP", "Ethernet"]:
            ttk.Radiobutton(proto_frame, text=p, value=p, variable=self.var_proto).pack(side="left", padx=6)

        # Dest / Source IP
        tk.Label(form, text="Destination IP:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=1, column=0, sticky="w", padx=5, pady=4)
        self.entry_dst_ip = ttk.Entry(form, width=22)
        self.entry_dst_ip.insert(0, "127.0.0.1")
        self.entry_dst_ip.grid(row=1, column=1, sticky="w", padx=5, pady=4)

        tk.Label(form, text="Source IP (Spoofing):", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=1, column=2, sticky="w", padx=5, pady=4)
        self.entry_src_ip = ttk.Entry(form, width=22)
        self.entry_src_ip.grid(row=1, column=3, sticky="w", padx=5, pady=4)

        # Ports & Flags
        tk.Label(form, text="Dest Port:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=2, column=0, sticky="w", padx=5, pady=4)
        self.entry_dport = ttk.Entry(form, width=10)
        self.entry_dport.insert(0, "80")
        self.entry_dport.grid(row=2, column=1, sticky="w", padx=5, pady=4)

        tk.Label(form, text="TCP Flags (e.g. S, SA, F):", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=2, column=2, sticky="w", padx=5, pady=4)
        self.entry_flags = ttk.Entry(form, width=10)
        self.entry_flags.insert(0, "S")
        self.entry_flags.grid(row=2, column=3, sticky="w", padx=5, pady=4)

        # Payload
        tk.Label(form, text="Custom Payload:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).grid(row=3, column=0, sticky="w", padx=5, pady=4)
        self.entry_payload = ttk.Entry(form, width=50)
        self.entry_payload.insert(0, "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
        self.entry_payload.grid(row=3, column=1, columnspan=3, sticky="w", padx=5, pady=4)

        # Buttons row
        btn_bar = tk.Frame(form, bg=self.theme["bg_card"])
        btn_bar.grid(row=4, column=0, columnspan=4, sticky="w", padx=5, pady=8)

        tk.Label(btn_bar, text="Count:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=4)
        self.entry_send_count = ttk.Entry(btn_bar, width=6)
        self.entry_send_count.insert(0, "1")
        self.entry_send_count.pack(side="left", padx=4)

        ttk.Button(btn_bar, text="👁️ Craft & Preview (.show())", command=self.preview_packet).pack(side="left", padx=8)
        ttk.Button(btn_bar, text="🚀 Transmit Packet", style="Accent.TButton", command=self.transmit).pack(side="left", padx=8)

        # Dissection Preview Box
        tk.Label(self, text="Crafted Packet Dissection Preview:", bg=self.theme["bg_dark"], fg=self.theme["accent_blue"], font=("DejaVu Sans", 9, "bold")).pack(anchor="w", padx=12, pady=(4, 2))
        self.preview_box = ScrolledText(self, height=12, bg=self.theme["bg_crust"], fg=self.theme["accent_green"], font=("DejaVu Sans Mono", 9))
        self.preview_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_packet(self):
        proto = self.var_proto.get()
        dst_ip = self.entry_dst_ip.get().strip() or "127.0.0.1"
        src_ip = self.entry_src_ip.get().strip() or None
        dport = int(self.entry_dport.get().strip() or 80)
        flags = self.entry_flags.get().strip() or "S"
        payload = self.entry_payload.get()

        if proto == "TCP":
            return craft_tcp_packet(dst_ip=dst_ip, dst_port=dport, src_ip=src_ip, flags=flags, payload=payload)
        elif proto == "UDP":
            return craft_udp_packet(dst_ip=dst_ip, dst_port=dport, src_ip=src_ip, payload=payload)
        elif proto == "ICMP":
            return craft_icmp_packet(dst_ip=dst_ip, src_ip=src_ip, payload=payload)
        elif proto == "Ethernet":
            inner = craft_icmp_packet(dst_ip=dst_ip, src_ip=src_ip)
            return craft_ethernet_packet(dst_mac="ff:ff:ff:ff:ff:ff", payload_pkt=inner)
        return None

    def preview_packet(self):
        pkt = self._build_packet()
        if pkt:
            self.current_packet = pkt
            dump = dissect_packet_details(pkt)
            self.preview_box.delete("1.0", tk.END)
            self.preview_box.insert(tk.END, dump)
            self.log("[+] Packet crafted and previewed.")

    def transmit(self):
        pkt = self._build_packet()
        if not pkt:
            return
        count = int(self.entry_send_count.get().strip() or 1)
        self.preview_packet()
        self.log(f"[*] Transmitting {count} packet(s)...")
        self.run_async(self._worker_send, on_success=self._on_send_done, pkt=pkt, count=count)

    def _worker_send(self, pkt, count: int):
        send_crafted_packet(pkt, count=count)

    def _on_send_done(self, _):
        self.log("[+] Packet transmission finished successfully.")
