"""
Unified Logger & Event Dispatcher for CLI and GUI.
"""

from datetime import datetime
from typing import Callable, List
from .config import COLORS


class ToolkitLogger:
    """Centralized logging system with terminal styling and subscriber dispatching."""

    def __init__(self):
        self._subscribers: List[Callable[[str, str], None]] = []

    def subscribe(self, callback: Callable[[str, str], None]):
        """Subscribe a callback to receive log events: callback(level, formatted_message)."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[str, str], None]):
        """Unsubscribe a callback."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _notify(self, level: str, msg: str):
        for sub in self._subscribers:
            try:
                sub(level, msg)
            except Exception:
                pass

    def info(self, msg: str):
        c_cyan = COLORS["CYAN"]
        c_reset = COLORS["RESET"]
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[*] {msg}"
        print(f"{c_cyan}[{timestamp}] {formatted}{c_reset}")
        self._notify("INFO", f"[{timestamp}] {formatted}")

    def success(self, msg: str):
        c_green = COLORS["GREEN"]
        c_reset = COLORS["RESET"]
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[+] {msg}"
        print(f"{c_green}[{timestamp}] {formatted}{c_reset}")
        self._notify("SUCCESS", f"[{timestamp}] {formatted}")

    def warning(self, msg: str):
        c_yellow = COLORS["YELLOW"]
        c_reset = COLORS["RESET"]
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[!] {msg}"
        print(f"{c_yellow}[{timestamp}] {formatted}{c_reset}")
        self._notify("WARNING", f"[{timestamp}] {formatted}")

    def error(self, msg: str):
        c_red = COLORS["RED"]
        c_reset = COLORS["RESET"]
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[-] {msg}"
        print(f"{c_red}[{timestamp}] {formatted}{c_reset}")
        self._notify("ERROR", f"[{timestamp}] {formatted}")


# Global Singleton Logger
logger = ToolkitLogger()
