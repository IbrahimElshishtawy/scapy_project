"""
Tab 6: Wi-Fi Manager & Saved Password Recovery.
"""

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from gui.tabs.base_tab import BaseTab
from services.wireless.wifi_manager import (
    scan_nearby_wifi,
    get_saved_wifi_passwords,
    connect_to_wifi,
)
from services.wireless.password_auditor import audit_password_strength


class WifiTab(BaseTab):
    """Nearby Wi-Fi discovery, saved password recovery, and password audit tab."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.build_ui()

    def build_ui(self):
        btn_bar = tk.Frame(self, bg=self.theme["bg_card"])
        btn_bar.pack(fill="x", padx=10, pady=10)

        ttk.Button(btn_bar, text="📡 Scan Nearby Wi-Fi", style="Accent.TButton", command=self.do_scan).pack(side="left", padx=5)
        ttk.Button(btn_bar, text="🔑 Retrieve Saved Passwords", command=self.do_saved).pack(side="left", padx=5)
        ttk.Button(btn_bar, text="🛡️ Audit Password Strength", command=self.do_audit).pack(side="left", padx=5)

        # Connect Frame
        conn_frame = tk.Frame(self, bg=self.theme["bg_card"])
        conn_frame.pack(fill="x", padx=10, pady=(0, 10))

        tk.Label(conn_frame, text="Connect to SSID:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=5)
        self.entry_ssid = ttk.Entry(conn_frame, width=18)
        self.entry_ssid.pack(side="left", padx=5)

        tk.Label(conn_frame, text="Password:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=5)
        self.entry_pwd = ttk.Entry(conn_frame, width=18, show="*")
        self.entry_pwd.pack(side="left", padx=5)

        ttk.Button(conn_frame, text="📶 Connect", command=self.do_connect).pack(side="left", padx=6)

        # Table
        cols = ("SSID", "BSSID", "Signal", "Security", "Channel", "Password / Info")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("SSID", width=180)
        self.tree.column("BSSID", width=160)
        self.tree.column("Signal", width=80, anchor="center")
        self.tree.column("Security", width=140)
        self.tree.column("Channel", width=70, anchor="center")
        self.tree.column("Password / Info", width=260)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.tree.bind("<ButtonRelease-1>", self.on_select_network)

    def do_scan(self):
        self.log("[*] Scanning nearby Wi-Fi networks (nmcli)...")
        for r in self.tree.get_children():
            self.tree.delete(r)
        self.run_async(self._worker_scan, on_success=self._on_scan_done)

    def _worker_scan(self):
        return scan_nearby_wifi()

    def _on_scan_done(self, networks):
        for n in networks:
            sig = f"{n.get('signal', '0')}% ({n.get('bars', '')})"
            self.tree.insert("", "end", values=(n["ssid"], n["bssid"], sig, n["security"], n["chan"], "Nearby AP"))
        self.log(f"[+] Found {len(networks)} nearby Wi-Fi network(s).")

    def do_saved(self):
        self.log("[*] Extracting saved Wi-Fi connections from NetworkManager...")
        for r in self.tree.get_children():
            self.tree.delete(r)
        self.run_async(self._worker_saved, on_success=self._on_saved_done)

    def _worker_saved(self):
        return get_saved_wifi_passwords()

    def _on_saved_done(self, saved):
        if saved and "error" in saved[0]:
            self.log(f"[-] {saved[0]['error']}")
            messagebox.showwarning("Permission Required", saved[0]["error"])
            return

        for s in saved:
            self.tree.insert("", "end", values=(s["ssid"], "Stored Profile", "N/A", s["security"], "-", s["password"]))
        self.log(f"[+] Retrieved {len(saved)} stored Wi-Fi profile(s).")

    def do_connect(self):
        ssid = self.entry_ssid.get().strip()
        pwd = self.entry_pwd.get().strip()
        if not ssid:
            messagebox.showwarning("Input Required", "Please enter or select an SSID.")
            return

        self.log(f"[*] Attempting connection to SSID: '{ssid}'...")
        self.run_async(self._worker_connect, on_success=self._on_connect_done, ssid=ssid, pwd=pwd)

    def _worker_connect(self, ssid: str, pwd: str):
        return connect_to_wifi(ssid, password=pwd)

    def _on_connect_done(self, result):
        success, msg = result
        if success:
            self.log(f"[+] Connected to Wi-Fi: {msg}")
            messagebox.showinfo("Wi-Fi Connected", f"Successfully connected to Wi-Fi!\n{msg}")
        else:
            self.log(f"[-] Wi-Fi connection failed: {msg}")
            messagebox.showerror("Connection Error", f"Failed to connect:\n{msg}")

    def do_audit(self):
        pwd = simpledialog.askstring("Audit Password", "Enter Wi-Fi password to audit security:", parent=self)
        if pwd:
            res = audit_password_strength(pwd)
            details = (
                f"Password: {pwd}\n"
                f"Score: {res['score']}/7\n"
                f"Rating: {res['rating']}\n"
                f"Entropy: {res['entropy']} bits\n"
                f"Feedback:\n- " + "\n- ".join(res["feedback"] or ["Good complexity."])
            )
            messagebox.showinfo("Password Security Audit", details)
            self.log(f"[*] Password audit verdict: {res['rating']} ({res['entropy']} bits)")

    def on_select_network(self, event):
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0], "values")
            ssid = vals[0]
            if ssid and not ssid.startswith("<"):
                self.entry_ssid.delete(0, tk.END)
                self.entry_ssid.insert(0, ssid)
