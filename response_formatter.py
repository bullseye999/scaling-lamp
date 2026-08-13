#!/usr/bin/env python3
# response_formatter.py - Clean CLI output for Ciph

import re
import os
import time
from datetime import datetime

class ResponseFormatter:
    """
    Makes Ciph's terminal output look clean, readable, and operator-grade.
    No clutter. No noise. Just signal.
    """

    def __init__(self):
        self.terminal_width = self._get_terminal_width()
        self.ciph_color   = '\033[96m'   # Cyan for Ciph
        self.user_color   = '\033[93m'   # Yellow for You
        self.system_color = '\033[90m'   # Grey for system messages
        self.alert_color  = '\033[91m'   # Red for alerts
        self.success_color= '\033[92m'   # Green for success
        self.reset        = '\033[0m'
        self.bold         = '\033[1m'
        self.dim          = '\033[2m'

    def _get_terminal_width(self) -> int:
        try:
            return os.get_terminal_size().columns
        except Exception:
            return 80

    # ─────────────────────────────────────────────
    # CORE PRINT METHODS
    # ─────────────────────────────────────────────

    def print_ciph(self, response: str):
        """Print Ciph's response — clean, readable"""
        print(f"\n{self.ciph_color}{self.bold}Ciph:{self.reset}", end=" ")
        # Word-wrap long responses
        formatted = self._wrap_text(response, indent=6)
        print(f"{self.ciph_color}{formatted}{self.reset}")

    def print_system(self, message: str):
        """Print system message — dimmed, unobtrusive"""
        print(f"\n{self.system_color}{self.dim}[ {message} ]{self.reset}")

    def print_alert(self, message: str):
        """Print alert — red, visible"""
        print(f"\n{self.alert_color}{self.bold}⚠ {message}{self.reset}")

    def print_success(self, message: str):
        """Print success — green"""
        print(f"\n{self.success_color}✓ {message}{self.reset}")

    def print_divider(self, style: str = 'thin'):
        """Print a clean divider"""
        width = self.terminal_width
        if style == 'thick':
            print(f"{self.system_color}{'═' * width}{self.reset}")
        elif style == 'thin':
            print(f"{self.system_color}{'─' * width}{self.reset}")
        elif style == 'dot':
            print(f"{self.system_color}{'·' * width}{self.reset}")

    def print_banner(self, ai_enabled: bool, module_count: int, memory_entities: int):
        """Clean startup banner"""
        width = self.terminal_width
        now = datetime.now().strftime("%H:%M · %d %b %Y")
        ai_tag     = "AI ✓"   if ai_enabled   else "AI ✗"
        status_line = f"  {now}  ·  Modules: {module_count}  ·  Memory: {memory_entities}  ·  {ai_tag}"

        print(f"\n{self.ciph_color}{'█' * width}{self.reset}")
        print(f"{self.ciph_color}{'█':<{width}}{self.reset}")
        title = "C I P H"
        padding = (width - len(title)) // 2
        print(f"{self.ciph_color}{'█'}{' ' * padding}{self.bold}{title}{self.reset}{self.ciph_color}{' ' * padding}{'█'}{self.reset}")
        print(f"{self.ciph_color}{'█':<{width}}{self.reset}")
        print(f"{self.ciph_color}{'█' * width}{self.reset}")
        print(f"{self.system_color}{self.dim}{status_line}{self.reset}\n")

    def print_thinking(self):
        """Animated thinking indicator"""
        frames = ['·  ', '·· ', '···']
        for _ in range(3):
            for frame in frames:
                print(f"\r{self.system_color}{self.dim}thinking {frame}{self.reset}", end='', flush=True)
                time.sleep(0.15)
        print('\r' + ' ' * 20 + '\r', end='')

    def format_command_response(self, response: str) -> str:
        """Format command responses — strip ‖ markers, clean up"""
        # Replace ‖ with clean formatting
        response = response.replace('‖', '').strip()
        # Clean multiple spaces
        response = re.sub(r'  +', ' ', response)
        return response

    def print_command_response(self, response: str):
        """Print command output cleanly"""
        cleaned = self.format_command_response(response)
        # Check if it's a multi-line report
        lines = cleaned.strip().split('\n')
        if len(lines) > 3:
            self.print_divider('thin')
            for line in lines:
                if line.strip():
                    print(f"  {self.system_color}{line}{self.reset}")
            self.print_divider('thin')
        else:
            print(f"\n{self.system_color}  {cleaned}{self.reset}")

    def print_status_grid(self, status_items: dict):
        """Print a clean status grid"""
        self.print_divider('thin')
        for key, value in status_items.items():
            key_str   = f"{key:<20}"
            val_color = self.success_color if any(
                word in str(value).upper() for word in ['ACTIVE', 'ON', 'READY', 'OK', 'ENABLED']
            ) else self.system_color
            print(f"  {self.dim}{key_str}{self.reset}  {val_color}{value}{self.reset}")
        self.print_divider('thin')

    def print_module_load(self, module_name: str, success: bool):
        """Print module load status"""
        if success:
            print(f"  {self.success_color}✓ {module_name} loaded{self.reset}")
        else:
            print(f"  {self.alert_color}✗ {module_name} failed{self.reset}")

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _wrap_text(self, text: str, indent: int = 0) -> str:
        """Word-wrap text to terminal width"""
        width = self.terminal_width - indent - 2
        words = text.split()
        lines = []
        current_line = []
        current_len = 0

        for word in words:
            if current_len + len(word) + 1 <= width:
                current_line.append(word)
                current_len += len(word) + 1
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_len = len(word)

        if current_line:
            lines.append(' '.join(current_line))

        indent_str = ' ' * indent
        return f"\n{indent_str}".join(lines)

    def get_user_prompt(self) -> str:
        """Styled user input prompt"""
        return f"{self.user_color}{self.bold}You:{self.reset} "