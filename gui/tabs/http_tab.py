"""
Tab 9: HTTP Reconnaissance & Security Headers.
"""

import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from gui.tabs.base_tab import BaseTab
from services.web.http_recon import (
    check_website,
    audit_security_headers,
    ip_threat_and_geo_lookup,
)


class HttpTab(BaseTab):
    """Web inspection, security headers auditing, and GeoIP lookup tab."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.build_ui()

    def build_ui(self):
        top = tk.Frame(self, bg=self.theme["bg_card"])
        top.pack(fill="x", padx=10, pady=10)

        tk.Label(top, text="Target URL/Domain:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=5)
        self.entry_url = ttk.Entry(top, width=32)
        self.entry_url.insert(0, "https://api.github.com")
        self.entry_url.pack(side="left", padx=5)

        ttk.Button(top, text="🌐 Inspect URL", style="Accent.TButton", command=self.do_inspect).pack(side="left", padx=4)
        ttk.Button(top, text="🛡️ Security Headers Audit", command=self.do_audit).pack(side="left", padx=4)
        ttk.Button(top, text="📍 IP Geo & Threat Intel", command=self.do_geoip).pack(side="left", padx=4)

        # Overview Status Card
        self.lbl_card = tk.Label(
            self,
            text="Enter URL and click 'Inspect URL' or 'Security Headers Audit'.",
            bg=self.theme["bg_surface"],
            fg=self.theme["accent_lavender"],
            font=("DejaVu Sans", 9),
            padx=10,
            pady=6,
            justify="left",
        )
        self.lbl_card.pack(fill="x", padx=10, pady=(0, 8))

        # Output Box
        self.out_box = ScrolledText(self, height=14, bg=self.theme["bg_crust"], fg=self.theme["accent_green"], font=("DejaVu Sans Mono", 9))
        self.out_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def do_inspect(self):
        url = self.entry_url.get().strip()
        self.log(f"[*] Sending HTTP GET request to: {url}...")
        self.out_box.delete("1.0", tk.END)
        self.run_async(self._worker_inspect, on_success=self._on_inspect_done, url=url)

    def _worker_inspect(self, url: str):
        return check_website(url)

    def _on_inspect_done(self, res):
        if not res["success"]:
            self.lbl_card.config(text=f"[-] HTTP Error: {res['error']}", fg=self.theme["accent_red"])
            self.log(f"[-] HTTP request failed: {res['error']}")
            return

        self.lbl_card.config(
            text=f"✅ Status: {res['status_code']}  |  ⚡ Latency: {res['latency_ms']}ms  |  🖥️ Server: {res['server']}",
            fg=self.theme["accent_green"],
        )
        self.log(f"[+] HTTP {res['status_code']} from {res['url']} ({res['latency_ms']}ms)")

        # Render headers
        self.out_box.insert(tk.END, f"=== HTTP RESPONSE HEADERS: {res['url']} ===\n\n")
        for k, v in res["headers"].items():
            self.out_box.insert(tk.END, f"{k:<35}: {v}\n")

    def do_audit(self):
        url = self.entry_url.get().strip()
        self.log(f"[*] Auditing HTTP security headers for: {url}...")
        self.out_box.delete("1.0", tk.END)
        self.run_async(self._worker_audit, on_success=self._on_audit_done, url=url)

    def _worker_audit(self, url: str):
        res = check_website(url)
        if res["success"]:
            audit = audit_security_headers(res["headers"])
            return res, audit
        return res, None

    def _on_audit_done(self, result):
        res, audit = result
        if not res["success"] or not audit:
            self.log(f"[-] Audit failed: {res.get('error', 'Connection failure')}")
            return

        score = audit["score_percent"]
        grade = audit["grade"]
        self.lbl_card.config(
            text=f"🛡️ Security Headers Grade: {grade} ({score}%)  |  Server: {res['server']}",
            fg=self.theme["accent_blue"],
        )

        self.out_box.insert(tk.END, f"=== HTTP SECURITY HEADERS AUDIT: {res['url']} ===\n")
        self.out_box.insert(tk.END, f"Security Score: {score}% (Grade: {grade})\n\n")

        self.out_box.insert(tk.END, "[+] PRESENT SECURITY HEADERS:\n")
        for h, val in audit["present_headers"].items():
            self.out_box.insert(tk.END, f"  ✓ {h:<45}: {val}\n")

        self.out_box.insert(tk.END, "\n[-] MISSING / RECOMMENDED HEADERS:\n")
        for h in audit["missing_headers"]:
            self.out_box.insert(tk.END, f"  ✗ {h}\n")

        self.log(f"[+] Security headers audit finished: Grade {grade} ({score}%)")

    def do_geoip(self):
        url = self.entry_url.get().strip()
        self.log(f"[*] Looking up GeoIP and Threat Intel for: {url}...")
        self.out_box.delete("1.0", tk.END)
        self.run_async(self._worker_geoip, on_success=self._on_geoip_done, url=url)

    def _worker_geoip(self, url: str):
        return ip_threat_and_geo_lookup(url)

    def _on_geoip_done(self, res):
        if not res["success"]:
            self.log(f"[-] GeoIP lookup error: {res.get('error')}")
            return

        d = res["data"]
        self.lbl_card.config(
            text=f"📍 Location: {d.get('city')}, {d.get('country')}  |  🏢 ISP: {d.get('isp')}  |  🌐 IP: {d.get('query')}",
            fg=self.theme["accent_lavender"],
        )
        self.out_box.insert(tk.END, f"=== IP GEOLOCATION & THREAT INTEL: {d.get('query')} ===\n\n")
        for k, v in d.items():
            self.out_box.insert(tk.END, f"{k:<20}: {v}\n")
        self.log(f"[+] GeoIP lookup resolved: {d.get('country')} ({d.get('isp')})")
