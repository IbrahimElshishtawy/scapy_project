#!/usr/bin/env python3
"""
Remote SSH & SFTP Automation Module (Paramiko Toolkit)
Provides tools for:
- Connecting to remote servers securely over SSH (SSHClient)
- Executing remote shell commands and capturing stdout/stderr (client.exec_command)
- Performing remote security audits & system health checks
- Securely transferring files and logs via SFTP (SFTPClient - get/put)
- Graceful session management and connection termination (client.close)
"""

import os
import sys
import time

try:
    import paramiko
except ImportError:
    paramiko = None


class RemoteSSHClient:
    """
    Wrapper around paramiko.SSHClient and SFTPClient
    for streamlined remote administration and security automation.
    """

    def __init__(self):
        if paramiko is None:
            raise ImportError("The 'paramiko' library is required. Install it using: pip install paramiko")
        self.client = paramiko.SSHClient()
        # Automatically trust unknown host keys (convenient for lab/admin environments)
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.is_connected = False
        self.host = None
        self.user = None

    def connect(
        self,
        hostname: str,
        port: int = 22,
        username: str = None,
        password: str = None,
        key_filename: str = None,
        timeout: int = 10
    ) -> bool:
        """
        Connects to a remote host over SSH using password or private key.
        """
        print(f"\n[*] Connecting to SSH server: {hostname}:{port} as '{username}' ...")
        try:
            kwargs = {
                "hostname": hostname,
                "port": port,
                "timeout": timeout,
                "look_for_keys": False,
                "allow_agent": False
            }
            if username:
                kwargs["username"] = username
            if password:
                kwargs["password"] = password
            if key_filename and os.path.exists(key_filename):
                kwargs["key_filename"] = key_filename

            self.client.connect(**kwargs)
            self.is_connected = True
            self.host = hostname
            self.user = username
            print(f"\033[92m[+] Successfully connected to {username}@{hostname}:{port}!\033[0m")
            return True

        except paramiko.AuthenticationException:
            print("\033[91m[-] Authentication failed: Invalid username, password, or key.\033[0m")
        except paramiko.SSHException as e:
            print(f"\033[91m[-] SSH protocol error:\033[0m {e}")
        except Exception as e:
            print(f"\033[91m[-] Connection error:\033[0m {e}")

        self.is_connected = False
        return False

    def exec_command(self, command: str, timeout: int = 30) -> tuple:
        """
        Executes a command on the remote machine.
        Returns: (exit_code, stdout_str, stderr_str)
        """
        if not self.is_connected:
            print("[-] Not connected to any SSH server.")
            return -1, "", "Not connected"

        print(f"\n[*] Executing remote command: \033[1m{command}\033[0m")
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out_str = stdout.read().decode("utf-8", errors="ignore").strip()
            err_str = stderr.read().decode("utf-8", errors="ignore").strip()

            return exit_code, out_str, err_str
        except Exception as e:
            return -1, "", str(e)

    def run_system_audit(self):
        """
        Runs a quick health and security audit on the remote Linux host.
        """
        if not self.is_connected:
            print("[-] Please connect to an SSH server first.")
            return

        print("\n" + "=" * 65)
        print(f"       REMOTE SYSTEM AUDIT: {self.user}@{self.host}")
        print("=" * 65)

        checks = [
            ("Operating System & Kernel", "uname -srmo"),
            ("Host Uptime & System Load", "uptime"),
            ("Currently Logged In Users", "who"),
            ("Disk Usage Overview", "df -h / | tail -n 1"),
            ("Listening Network Ports", "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null | head -n 10"),
            ("Recent Sudo/Auth Failures", "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -n 3 || echo 'No readable auth log'")
        ]

        for title, cmd in checks:
            print(f"\n[+] \033[1m{title}\033[0m")
            print("-" * 50)
            code, out, err = self.exec_command(cmd, timeout=10)
            if out:
                print(out)
            elif err:
                print(f"\033[90m{err}\033[0m")
            else:
                print("\033[90m(No output)\033[0m")

        print("=" * 65 + "\n")

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        Downloads a file from remote server to local machine via SFTP (e.g. log fetching).
        """
        if not self.is_connected:
            print("[-] Please connect to an SSH server first.")
            return False

        print(f"\n[*] [SFTP] Downloading '{remote_path}' -> '{local_path}' ...")
        try:
            sftp = self.client.open_sftp()
            os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
            sftp.get(remote_path, local_path)
            sftp.close()
            print(f"\033[92m[+] File downloaded successfully ({os.path.getsize(local_path)} bytes)!\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[-] SFTP download failed:\033[0m {e}")
            return False

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Uploads a local file to the remote server via SFTP.
        """
        if not self.is_connected:
            print("[-] Please connect to an SSH server first.")
            return False

        if not os.path.exists(local_path):
            print(f"[-] Local file '{local_path}' does not exist.")
            return False

        print(f"\n[*] [SFTP] Uploading '{local_path}' -> '{remote_path}' ...")
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            print(f"\033[92m[+] File uploaded successfully!\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[-] SFTP upload failed:\033[0m {e}")
            return False

    def close(self):
        """Terminates the SSH connection gracefully."""
        if self.is_connected:
            self.client.close()
            self.is_connected = False
            print(f"[*] SSH connection to {self.host} closed.")


def run_interactive_ssh_menu():
    """Interactive CLI menu for the Paramiko SSH module."""
    if paramiko is None:
        print("[-] Paramiko library is not installed. Please run: pip install paramiko")
        return

    ssh_wrapper = RemoteSSHClient()

    while True:
        status = f"\033[92mConnected ({ssh_wrapper.user}@{ssh_wrapper.host})\033[0m" if ssh_wrapper.is_connected else "\033[90mDisconnected\033[0m"
        print("\n" + "=" * 65)
        print(f"   🔐 REMOTE SSH & SFTP AUTOMATION (Paramiko) [{status}]")
        print("=" * 65)
        print("1) Connect to Remote Host (SSHClient.connect)")
        print("2) Execute Remote Command (client.exec_command)")
        print("3) Run Automated Remote Security Audit")
        print("4) Download Remote File / Log (SFTP get)")
        print("5) Upload Local File to Remote Host (SFTP put)")
        print("6) Disconnect Session (client.close)")
        print("7) Back to Main Menu")
        print("=" * 65)

        choice = input("Select an option [1-7]: ").strip()

        if choice == "1":
            host = input("Enter remote host/IP (e.g. 192.168.1.1 or myserver.com): ").strip()
            if not host:
                print("[-] Host is required.")
                continue
            port_in = input("Enter SSH port (default: 22): ").strip()
            port = int(port_in) if port_in.isdigit() else 22
            user = input("Enter username: ").strip() or "root"
            auth_type = input("Authenticate with [P]assword or [K]ey file? (P/k): ").strip().lower()

            if auth_type == "k":
                key_path = input("Enter path to private key file (~/.ssh/id_rsa): ").strip()
                ssh_wrapper.connect(hostname=host, port=port, username=user, key_filename=key_path)
            else:
                import getpass
                pwd = getpass.getpass("Enter SSH password: ")
                ssh_wrapper.connect(hostname=host, port=port, username=user, password=pwd)

        elif choice == "2":
            if not ssh_wrapper.is_connected:
                print("[-] Not connected. Choose option 1 first.")
                continue
            cmd = input("Enter remote shell command to execute: ").strip()
            if cmd:
                code, out, err = ssh_wrapper.exec_command(cmd)
                print(f"Exit Code: {code}")
                if out:
                    print("\n--- [ STDOUT ] ---")
                    print(out)
                if err:
                    print("\n--- [ STDERR ] ---")
                    print(err)

        elif choice == "3":
            if not ssh_wrapper.is_connected:
                print("[-] Not connected. Choose option 1 first.")
                continue
            ssh_wrapper.run_system_audit()

        elif choice == "4":
            if not ssh_wrapper.is_connected:
                print("[-] Not connected. Choose option 1 first.")
                continue
            remote_p = input("Enter remote file path to download (e.g. /var/log/syslog): ").strip()
            local_p = input("Enter local destination path (e.g. captures/remote_syslog.log): ").strip()
            if remote_p and local_p:
                ssh_wrapper.download_file(remote_p, local_p)

        elif choice == "5":
            if not ssh_wrapper.is_connected:
                print("[-] Not connected. Choose option 1 first.")
                continue
            local_p = input("Enter local file path to upload: ").strip()
            remote_p = input("Enter remote destination path: ").strip()
            if local_p and remote_p:
                ssh_wrapper.upload_file(local_p, remote_p)

        elif choice == "6":
            ssh_wrapper.close()

        elif choice == "7":
            ssh_wrapper.close()
            break
        else:
            print("[-] Invalid option. Choose 1-7.")


if __name__ == "__main__":
    run_interactive_ssh_menu()
