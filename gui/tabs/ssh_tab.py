"""
Tab 10: Remote SSH & SFTP Automation (Paramiko).
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
from gui.tabs.base_tab import BaseTab
from services.remote.ssh_manager import RemoteSSHClient


class SshTab(BaseTab):
    """Remote SSH execution, security diagnostics, and SFTP automation tab."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.ssh = RemoteSSHClient()
        self.build_ui()

    def build_ui(self):
        # Connection Row
        conn_bar = tk.Frame(self, bg=self.theme["bg_card"])
        conn_bar.pack(fill="x", padx=10, pady=8)

        tk.Label(conn_bar, text="Host:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=4)
        self.entry_host = ttk.Entry(conn_bar, width=16)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.pack(side="left", padx=4)

        tk.Label(conn_bar, text="Port:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=4)
        self.entry_port = ttk.Entry(conn_bar, width=6)
        self.entry_port.insert(0, "22")
        self.entry_port.pack(side="left", padx=4)

        tk.Label(conn_bar, text="User:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=4)
        self.entry_user = ttk.Entry(conn_bar, width=12)
        self.entry_user.insert(0, "root")
        self.entry_user.pack(side="left", padx=4)

        tk.Label(conn_bar, text="Password:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=4)
        self.entry_pwd = ttk.Entry(conn_bar, width=14, show="*")
        self.entry_pwd.pack(side="left", padx=4)

        self.btn_connect = ttk.Button(conn_bar, text="🔐 Connect", style="Accent.TButton", command=self.toggle_connect)
        self.btn_connect.pack(side="left", padx=8)

        # Command & Actions Bar
        act_bar = tk.Frame(self, bg=self.theme["bg_card"])
        act_bar.pack(fill="x", padx=10, pady=(0, 8))

        tk.Label(act_bar, text="Command:", bg=self.theme["bg_card"], fg=self.theme["fg_text"]).pack(side="left", padx=4)
        self.entry_cmd = ttk.Entry(act_bar, width=32)
        self.entry_cmd.insert(0, "uname -a && uptime")
        self.entry_cmd.pack(side="left", padx=4)

        ttk.Button(act_bar, text="▶ Exec", command=self.do_exec).pack(side="left", padx=4)
        ttk.Button(act_bar, text="🔍 Security Audit", command=self.do_audit).pack(side="left", padx=4)
        ttk.Button(act_bar, text="📥 SFTP Download", command=self.do_sftp_download).pack(side="left", padx=4)

        # Output Terminal Box
        self.term_box = ScrolledText(self, height=14, bg=self.theme["bg_crust"], fg=self.theme["accent_green"], font=("DejaVu Sans Mono", 9))
        self.term_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def toggle_connect(self):
        if not self.ssh.is_connected:
            host = self.entry_host.get().strip()
            port = int(self.entry_port.get().strip() or 22)
            user = self.entry_user.get().strip()
            pwd = self.entry_pwd.get().strip() or None

            self.log(f"[*] Connecting to SSH: {user}@{host}:{port} ...")
            self.run_async(self._worker_connect, on_success=self._on_connect_done, host=host, port=port, user=user, pwd=pwd)
        else:
            self.ssh.close()
            self.btn_connect.config(text="🔐 Connect", style="Accent.TButton")
            self.log("[*] SSH connection closed.")

    def _worker_connect(self, host: str, port: int, user: str, pwd: str):
        return self.ssh.connect(hostname=host, port=port, username=user, password=pwd)

    def _on_connect_done(self, result):
        success, msg = result
        if success:
            self.btn_connect.config(text="🔓 Disconnect", style="Danger.TButton")
            self.log(f"[+] {msg}")
            self.term_box.insert(tk.END, f"[+] {msg}\nType commands above and click 'Exec'.\n\n")
        else:
            self.log(f"[-] SSH connection failed: {msg}")
            messagebox.showerror("SSH Error", f"Connection Failed:\n{msg}")

    def do_exec(self):
        if not self.ssh.is_connected:
            messagebox.showwarning("Not Connected", "Please connect to an SSH server first.")
            return

        cmd = self.entry_cmd.get().strip()
        if not cmd:
            return

        self.log(f"[*] Executing remote command: '{cmd}'...")
        self.term_box.insert(tk.END, f"$ {cmd}\n")
        self.run_async(self._worker_exec, on_success=self._on_exec_done, cmd=cmd)

    def _worker_exec(self, cmd: str):
        return self.ssh.execute_command(cmd)

    def _on_exec_done(self, res):
        out = res["stdout"] or res["stderr"]
        self.term_box.insert(tk.END, f"{out}\n")
        self.term_box.see(tk.END)
        self.log(f"[+] Command completed (exit code: {res['exit_code']})")

    def do_audit(self):
        if not self.ssh.is_connected:
            messagebox.showwarning("Not Connected", "Please connect to an SSH server first.")
            return

        self.log("[*] Running automated remote system security audit...")
        self.term_box.insert(tk.END, "\n=== REMOTE SECURITY AUDIT ===\n")
        self.run_async(self._worker_audit, on_success=self._on_audit_done)

    def _worker_audit(self):
        return self.ssh.run_system_audit()

    def _on_audit_done(self, audit):
        for k, v in audit.items():
            self.term_box.insert(tk.END, f"\n[+] {k.upper()}:\n{v}\n")
        self.term_box.see(tk.END)
        self.log("[+] Remote security audit completed.")

    def do_sftp_download(self):
        if not self.ssh.is_connected:
            messagebox.showwarning("Not Connected", "Please connect to an SSH server first.")
            return

        rpath = simpledialog.askstring("SFTP Download", "Enter remote file path (e.g. /var/log/syslog):", parent=self)
        if not rpath:
            return

        lpath = simpledialog.askstring("SFTP Download", "Enter local destination file path:", initialvalue="captures/downloaded.log", parent=self)
        if not lpath:
            return

        self.log(f"[*] Downloading {rpath} -> {lpath} via SFTP...")
        self.run_async(self._worker_sftp, on_success=self._on_sftp_done, rpath=rpath, lpath=lpath)

    def _worker_sftp(self, rpath: str, lpath: str):
        return self.ssh.sftp_download(rpath, lpath)

    def _on_sftp_done(self, result):
        success, msg = result
        if success:
            self.log(f"[+] {msg}")
            messagebox.showinfo("SFTP Download", msg)
        else:
            self.log(f"[-] SFTP failed: {msg}")
            messagebox.showerror("SFTP Error", msg)
