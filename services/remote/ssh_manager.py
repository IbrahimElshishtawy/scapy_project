"""
Remote SSH Administration, Security Auditing, & SFTP File Transfer Service (Paramiko).
"""

from typing import Dict, Any, Optional, Tuple
import paramiko


class RemoteSSHClient:
    """Paramiko SSHClient and SFTP wrapper for remote administration."""

    def __init__(self):
        self.client: Optional[paramiko.SSHClient] = None
        self.hostname: Optional[str] = None
        self.port: int = 22
        self.username: Optional[str] = None
        self.is_connected: bool = False

    def connect(
        self,
        hostname: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        timeout: int = 10,
    ) -> Tuple[bool, str]:
        """Connects to remote SSH server with password or private key."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs: Dict[str, Any] = {
                "hostname": hostname.strip(),
                "port": int(port),
                "username": username.strip(),
                "timeout": timeout,
            }
            if password:
                connect_kwargs["password"] = password
            if key_filename:
                connect_kwargs["key_filename"] = key_filename.strip()

            self.client.connect(**connect_kwargs)
            self.hostname = hostname
            self.port = port
            self.username = username
            self.is_connected = True
            return True, f"Connected to {username}@{hostname}:{port}"
        except Exception as e:
            self.is_connected = False
            return False, str(e)

    def execute_command(self, cmd: str, timeout: int = 30) -> Dict[str, Any]:
        """Executes a command on the remote host and returns stdout and stderr."""
        if not self.is_connected or not self.client:
            return {"success": False, "exit_code": -1, "stdout": "", "stderr": "Not connected to SSH."}

        try:
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="ignore")
            err = stderr.read().decode("utf-8", errors="ignore")
            exit_code = stdout.channel.recv_exit_status()
            return {"success": exit_code == 0, "exit_code": exit_code, "stdout": out, "stderr": err}
        except Exception as e:
            return {"success": False, "exit_code": -1, "stdout": "", "stderr": str(e)}

    def run_system_audit(self) -> Dict[str, str]:
        """Runs basic remote system security diagnostics."""
        audit_commands = {
            "os_kernel": "uname -a",
            "uptime": "uptime",
            "active_users": "who || w",
            "listening_ports": "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null",
            "failed_logins": "grep -i 'failed' /var/log/auth.log 2>/dev/null | tail -n 10 || echo 'No auth log accessible'",
        }
        results = {}
        for key, cmd in audit_commands.items():
            res = self.execute_command(cmd)
            results[key] = res["stdout"] if res["success"] else res["stderr"]
        return results

    def sftp_download(self, remote_path: str, local_path: str) -> Tuple[bool, str]:
        """Downloads a remote file via SFTP."""
        if not self.is_connected or not self.client:
            return False, "Not connected to SSH."
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True, f"Successfully downloaded {remote_path} to {local_path}"
        except Exception as e:
            return False, str(e)

    def sftp_upload(self, local_path: str, remote_path: str) -> Tuple[bool, str]:
        """Uploads a local file via SFTP."""
        if not self.is_connected or not self.client:
            return False, "Not connected to SSH."
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True, f"Successfully uploaded {local_path} to {remote_path}"
        except Exception as e:
            return False, str(e)

    def close(self):
        """Closes active SSH connection."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
        self.is_connected = False
