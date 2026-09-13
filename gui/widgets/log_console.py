"""
Real-time Log Console Widget.
"""

import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.scrolledtext import ScrolledText
from datetime import datetime
from gui.theme import THEME
from core.logger import logger


class LogConsoleWidget(tk.LabelFrame):
    """Scrolled log viewer with automatic timestamps, clearing, and saving."""

    def __init__(self, parent, height: int = 7):
        super().__init__(
            parent,
            text=" 📝 Real-Time System Log & Activity Console ",
            bg=THEME["bg_card"],
            fg=THEME["accent_blue"],
            font=("DejaVu Sans", 9, "bold"),
        )
        self.pack(fill="x", side="bottom", padx=10, pady=(0, 5))

        self.text_box = ScrolledText(
            self,
            height=height,
            bg=THEME["bg_crust"],
            fg=THEME["fg_text"],
            font=("DejaVu Sans Mono", 9),
            insertbackground="white",
            relief="flat",
        )
        self.text_box.pack(fill="x", padx=5, pady=5)

        # Control row
        btn_row = tk.Frame(self, bg=THEME["bg_card"])
        btn_row.pack(fill="x", padx=5, pady=(0, 4))

        ttk.Button(btn_row, text="Clear Logs", command=self.clear_logs).pack(side="right", padx=3)
        ttk.Button(btn_row, text="Save Logs to File", command=self.save_logs).pack(side="right", padx=3)

        # Subscribe to core logger events
        logger.subscribe(self._on_logger_event)

    def _on_logger_event(self, level: str, msg: str):
        self.after(0, lambda: self.log_direct(msg))

    def log_direct(self, text: str):
        self.text_box.insert(tk.END, f"{text}\n")
        self.text_box.see(tk.END)

    def log(self, text: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_direct(f"[{timestamp}] {text}")

    def clear_logs(self):
        self.text_box.delete("1.0", tk.END)

    def save_logs(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=f"scapy_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.text_box.get("1.0", tk.END))
                self.log(f"[+] Logs successfully saved to: {path}")
            except Exception as e:
                self.log(f"[-] Failed to save logs: {e}")
