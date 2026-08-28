#!/usr/bin/env python3
# response_formatter.py - Clean CLI output for Ciph

import re
import os
import time
import textwrap
from datetime import datetime
from typing import Optional, Dict, Any

class ResponseFormatter:
    """
    Makes Ciph's terminal output look clean, readable, and operator-grade.
    Preserves multi-line formatting, ASCII layouts, tables, and lists.
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
            w = os.get_terminal_size().columns
            return max(60, min(w, 120))
        except Exception:
            return 80

    # ─────────────────────────────────────────────
    # CORE PRINT METHODS
    # ─────────────────────────────────────────────

    def print_ciph(self, response: str):
        """Print Ciph's response with proper line and block preservation."""
        if not response:
            return
        # Clean ‖ delimiters if present
        clean_res = response.strip()
        if clean_res.startswith("‖") and clean_res.endswith("‖"):
            clean_res = clean_res[1:-1].strip()

        formatted = self._wrap_text(clean_res, indent=2)
        print(f"\n{self.ciph_color}{self.bold}🕶️ Ciph:{self.reset}\n{self.ciph_color}{formatted}{self.reset}")

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
        ai_tag = "AI ✓" if ai_enabled else "AI ✗"
        status_line = f"  {now}  ·  Modules: {module_count}  ·  Memory: {memory_entities}  ·  {ai_tag}"

        print(f"\n{self.ciph_color}{'█' * width}{self.reset}")
        print(f"{self.ciph_color}{'█':<{width}}{self.reset}")
        title = "C I P H  3 . 0"
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
                time.sleep(0.12)
        print('\r' + ' ' * 20 + '\r', end='')

    def format_command_response(self, response: str) -> str:
        """Format command responses — clean up outer ‖ markers while preserving newlines."""
        if not response:
            return ""
        resp = response.strip()
        if resp.startswith("‖") and resp.endswith("‖"):
            resp = resp[1:-1].strip()
        return resp

    def print_command_response(self, response: str):
        """Print command output cleanly preserving layout."""
        cleaned = self.format_command_response(response)
        lines = cleaned.split('\n')
        if len(lines) > 3:
            self.print_divider('thin')
            for line in lines:
                print(f"  {line}")
            self.print_divider('thin')
        else:
            print(f"\n  {cleaned}")

    def print_status_grid(self, status_items: dict):
        """Print a clean status grid"""
        self.print_divider('thin')
        for key, value in status_items.items():
            key_str = f"{key:<22}"
            val_color = self.success_color if any(
                word in str(value).upper() for word in ['ACTIVE', 'ON', 'READY', 'OK', 'ENABLED', 'SECURE']
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
        """
        Word-wraps text preserving explicit linebreaks (\n), ASCII art, lists, and headers.
        Never smashes multi-line blocks into single paragraphs.
        """
        if not text:
            return ""

        max_width = max(40, self.terminal_width - indent - 2)
        indent_str = ' ' * indent
        raw_lines = text.split('\n')
        out_lines = []

        for line in raw_lines:
            # Preserve raw ASCII frames, boxes, and dividers directly
            if any(box_char in line for box_char in ['╔', '║', '═', '╚', '┌', '│', '└', '─', '█', '▓']):
                out_lines.append(f"{indent_str}{line}")
                continue

            if len(line.rstrip()) <= max_width:
                out_lines.append(f"{indent_str}{line}")
            else:
                # Detect leading whitespace for indentation preservation
                leading_spaces = len(line) - len(line.lstrip(' '))
                sub_indent = indent_str + (' ' * leading_spaces)
                wrapped = textwrap.wrap(
                    line,
                    width=max_width,
                    initial_indent=indent_str,
                    subsequent_indent=sub_indent + "  "
                )
                out_lines.extend(wrapped)

        return "\n".join(out_lines)

    def get_user_prompt(self) -> str:
        """Styled user input prompt"""
        return f"{self.user_color}{self.bold}You:{self.reset} "