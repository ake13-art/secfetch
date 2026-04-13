"""Shared ANSI color constants."""
from __future__ import annotations

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"
CLEAR = "\033[2J\033[H"  # clear screen and move cursor to top-left

STATUS_COLORS = {"ok": GREEN, "warn": YELLOW, "bad": RED, "info": CYAN}
ICONS = {"ok": "\u2714", "warn": "\u26a0", "bad": "\u2716", "info": "\u2022"}


def colorize(status: str, text: str) -> str:
    return f"{STATUS_COLORS.get(status, '')}{text}{RESET}"
