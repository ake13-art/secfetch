from __future__ import annotations

import functools
import re

from secfetch.core.scoring import calculate_score
from secfetch.core.types import CheckResult
from secfetch.ui.colors import CLEAR, GREEN, ICONS, RED, RESET, YELLOW, colorize

# ─────────────────────────────────────────────
#  Short mode layout selector
#  "box"  = categories in a box (default)
#  "side" = logo left, info right
# ─────────────────────────────────────────────
SHORT_LAYOUT = "box"
# SHORT_LAYOUT = "side"

_NAME_WIDTH = 22
_CATEGORY_WIDTH = 20
_SCORE_BAR_WIDTH_FULL = 12  # score bar width in full/live output
_SCORE_BAR_WIDTH_SHORT = 15  # score bar width in short output
_SCORE_GOOD = 75  # threshold for green score bar
_SCORE_WARN = 40  # threshold for yellow score bar


# ─────────────────────────────────────────────
#  ASCII logo
# ─────────────────────────────────────────────
LOGO_FULL = r"""
                   ____     __       __
   ________  _____/ __/__  / /______/ /_
  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/
"""

LOGO_SHORT = [
    r"                   ____     __       __",
    r"   ________  _____/ __/__  / /______/ /_",
    r"  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \\",
    r" (__  )  __/ /__/ __/  __/ /_/ /__/ / / /",
    r"/____/\___/\___/_/  \___/\__/\___/_/ /_/",
]

# display order and titles for categories
CATEGORY_ORDER = [
    "system",
    "kernel_security",
    "kernel_hardening",
    "network",
    "filesystem",
]
CATEGORY_TITLES = {
    "system": "System",
    "kernel_security": "Kernel Security",
    "kernel_hardening": "Kernel Hardening",
    "network": "Network",
    "filesystem": "Filesystem",
}


def score_bar(score: int, width: int = 15) -> str:
    filled = int((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    color = GREEN if score >= _SCORE_GOOD else YELLOW if score >= _SCORE_WARN else RED
    return f"{color}[{bar}]{RESET}"


_ANSI_RE = re.compile(r"\033\[[0-9;]*[A-Za-z]")


def _has_ansi(text: str) -> bool:
    return bool(_ANSI_RE.search(text))


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _format_check_result(results: list[CheckResult], name: str) -> str:
    """Format a single named check result for short output modes."""
    result = next((x for x in results if x["name"] == name), None)
    if result is None:
        return "N/A"
    return colorize(result["status"], f"{ICONS.get(result['status'], '•')} {result['value']}")


# ─────────────────────────────────────────────
#  Full output
# ─────────────────────────────────────────────


def print_results(results: list[CheckResult]) -> None:
    score, cat_scores = calculate_score(results)

    print(LOGO_FULL)

    grouped: dict[str, list[CheckResult]] = {}
    for result in results:
        grouped.setdefault(result["category"], []).append(result)

    for cat in CATEGORY_ORDER:
        if cat not in grouped:
            continue
        print(f"  {CATEGORY_TITLES.get(cat, cat)}")
        print("  " + "─" * 40)
        for result in grouped[cat]:
            icon = colorize(result["status"], ICONS.get(result["status"], "•"))
            name = result["name"].ljust(_NAME_WIDTH)
            val = (
                result["value"]
                if _has_ansi(result["value"])
                else colorize(result["status"], result["value"])
            )
            print(f"    {icon}  {name}  {val}")
        print()

    print("  Security Score")
    print("  " + "─" * 40)
    for cat in CATEGORY_ORDER:
        if cat not in cat_scores:
            continue
        title = CATEGORY_TITLES.get(cat, cat).ljust(_CATEGORY_WIDTH)
        s = cat_scores[cat]
        print(f"    {title}  {score_bar(s, width=_SCORE_BAR_WIDTH_FULL)}  {s}/100")
    print("  " + "─" * 40)
    print(
        f"    {'Total'.ljust(_CATEGORY_WIDTH)}  {score_bar(score, width=_SCORE_BAR_WIDTH_FULL)}  {score}/100"
    )
    print()


# ─────────────────────────────────────────────
#  Live output
# ─────────────────────────────────────────────


def print_results_live(results: list[CheckResult], interval: int) -> None:
    print(CLEAR, end="", flush=True)
    print_results(results)
    print(f"  Refreshing every {interval}s  —  Press Q + Enter to stop")


# ─────────────────────────────────────────────
#  Short output – Box variant
# ─────────────────────────────────────────────


def _short_box(results: list[CheckResult]) -> None:
    score, _ = calculate_score(results)
    fmt = functools.partial(_format_check_result, results)
    kernel = next((r["value"] for r in results if r["name"] == "Kernel"), "?")

    lines = [
        f"  {'System':<10}Kernel: {kernel:<20}  Secure Boot: {fmt('Secure Boot')}",
        f"  {'Security':<10}ASLR: {fmt('ASLR'):<22}  Lockdown: {fmt('Lockdown')}",
        f"  {'Network':<10}Firewall: {fmt('Firewall Rules'):<18}  Ports: {fmt('Open Ports')}",
        f"  {'Score':<10}{score_bar(score, width=_SCORE_BAR_WIDTH_SHORT)}  {score}/100",
    ]

    print()
    width = max(len(_strip_ansi(line)) for line in lines) + 4
    print("  ┌" + "─" * (width - 2) + "┐")
    for line in lines:
        pad = width - len(_strip_ansi(line)) - 2
        print("  │" + line + " " * pad + "│")
    print("  └" + "─" * (width - 2) + "┘")
    print()


# ─────────────────────────────────────────────
#  Short output – Side variant
# ─────────────────────────────────────────────


def _short_side(results: list[CheckResult]) -> None:
    score, _ = calculate_score(results)
    fmt = functools.partial(_format_check_result, results)
    kernel = next((r["value"] for r in results if r["name"] == "Kernel"), "?")

    info_lines = [
        f"  Kernel       {kernel}",
        f"  Secure Boot  {fmt('Secure Boot')}",
        f"  ASLR         {fmt('ASLR')}",
        f"  Lockdown     {fmt('Lockdown')}",
        f"  Firewall     {fmt('Firewall Rules')}",
        f"  Ports        {fmt('Open Ports')}",
        f"  Score        {score_bar(score, width=_SCORE_BAR_WIDTH_FULL)}  {score}/100",
    ]

    max_lines = max(len(LOGO_SHORT), len(info_lines))
    for i in range(max_lines):
        left = LOGO_SHORT[i] if i < len(LOGO_SHORT) else " " * 42
        right = info_lines[i] if i < len(info_lines) else ""
        print(left + right)
    print()


# ─────────────────────────────────────────────
#  Entry points
# ─────────────────────────────────────────────


def print_results_short(results: list[CheckResult]) -> None:
    if SHORT_LAYOUT == "side":
        _short_side(results)
    else:
        _short_box(results)
