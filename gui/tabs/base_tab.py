"""
Base Tab Class with Threaded Execution Support.
"""

import threading
from typing import Callable, Any, Optional
import tkinter as tk
from tkinter import ttk
from gui.theme import THEME
from gui.widgets.packet_dialog import PacketDissectionDialog


class BaseTab(ttk.Frame):
    """Base class for all toolkit notebook tabs."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.theme = THEME

    def log(self, message: str):
        """Logs message to the global activity console."""
        self.app.log(message)

    def run_async(
        self,
        worker_func: Callable,
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        *args,
        **kwargs,
    ):
        """
        Executes worker_func(*args, **kwargs) in a background thread.
        Safely dispatches on_success or on_error back to the Tk mainloop thread.
        """
        def _thread_target():
            try:
                result = worker_func(*args, **kwargs)
                if on_success:
                    self.after(0, lambda: on_success(result))
            except Exception as exc:
                self.log(f"[-] Error in background task: {exc}")
                if on_error:
                    self.after(0, lambda: on_error(exc))

        thread = threading.Thread(target=_thread_target, daemon=True)
        thread.start()
        return thread

    def show_packet_dialog(self, packet, title: str = "Packet Details"):
        """Opens deep packet inspection dialog."""
        PacketDissectionDialog(self, packet, packet_title=title)
