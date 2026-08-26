"""Shared ANSI color constants and color-eligibility helper."""
from __future__ import annotations

import os
import sys

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"
CLEAR = "\033[2J\033[H"

STATUS_COLORS = {"ok": GREEN, "warn": YELLOW, "bad": RED, "info": CYAN}
ICONS = {"ok": "\u2714", "warn": "\u26a0", "bad": "\u2716", "info": "\u2022"}


def use_color() -> bool:
    """Return True when ANSI color output should be emitted on stdout.

    Honours the ``NO_COLOR`` convention (https://no-color.org), the
    ``TERM=dumb`` terminal, and TTY detection on stdout.
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return sys.stdout.isatty()


def colorize(status: str, text: str) -> str:
    """Wrap *text* in the color matching *status*, or return *text* unchanged
    when color output is disabled (NO_COLOR, non-TTY, TERM=dumb)."""
    if not use_color():
        return text
    return f"{STATUS_COLORS.get(status, '')}{text}{RESET}"
