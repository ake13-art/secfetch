import sys
import re
import os
from secfetch.core.scoring import calculate_score

# ─────────────────────────────────────────────
#  Short mode layout selector
#  "box"  = categories in a box (default)
#  "side" = logo left, info right
# ─────────────────────────────────────────────
SHORT_LAYOUT = "box"
# SHORT_LAYOUT = "side"

# status icons
ICONS = {"ok": "✔", "warn": "⚠", "bad": "✖", "info": "•"}

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

# color codes
RED, YELLOW, GREEN, CYAN, RESET = (
    "\033[31m",
    "\033[33m",
    "\033[32m",
    "\033[36m",
    "\033[0m",
)
STATUS_COLORS = {"ok": GREEN, "warn": YELLOW, "bad": RED, "info": CYAN}


def colorize(status: str, text: str) -> str:
    return f"{STATUS_COLORS.get(status, '')}{text}{RESET}"


def score_bar(score: int, width: int = 15) -> str:
    filled = int((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    color = GREEN if score >= 75 else YELLOW if score >= 40 else RED
    return f"{color}[{bar}]{RESET}"


def _strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


# ─────────────────────────────────────────────
#  Full output
# ─────────────────────────────────────────────


def print_results(results: list[dict]) -> None:
    score, cat_scores = calculate_score(results)

    print(LOGO_FULL)

    grouped = {}
    for r in results:
        grouped.setdefault(r["category"], []).append(r)

    for cat in CATEGORY_ORDER:
        if cat not in grouped:
            continue
        print(f"  {CATEGORY_TITLES.get(cat, cat)}")
        print("  " + "─" * 40)
        for r in grouped[cat]:
            icon = colorize(r["status"], ICONS.get(r["status"], "•"))
            name = r["name"].ljust(22)
            val = (
                r["value"]
                if "\033[" in r["value"]
                else colorize(r["status"], r["value"])
            )
            print(f"    {icon}  {name}  {val}")
        print()

    print("  Security Score")
    print("  " + "─" * 40)
    for cat in CATEGORY_ORDER:
        if cat not in cat_scores:
            continue
        title = CATEGORY_TITLES.get(cat, cat).ljust(20)
        s = cat_scores[cat]
        print(f"    {title}  {score_bar(s, width=12)}  {s}/100")
    print("  " + "─" * 40)
    print(f"    {'Total'.ljust(20)}  {score_bar(score, width=12)}  {score}/100")
    print()


# ─────────────────────────────────────────────
#  Live output
# ─────────────────────────────────────────────


def print_results_live(results: list[dict], interval: int) -> None:
    print("\033[2J\033[H", end="", flush=True)
    print_results(results)
    print(f"  Refreshing every {interval}s  —  Press Q + Enter to stop")


# ─────────────────────────────────────────────
#  Short output – Box variant
# ─────────────────────────────────────────────


def _short_box(results: list[dict]) -> None:
    score, _ = calculate_score(results)

    def fmt(name) -> str:
        r = next((x for x in results if x["name"] == name), None)
        if r is None:
            return "N/A"
        return colorize(r["status"], f"{ICONS.get(r['status'], '•')} {r['value']}")

    kernel = next((r["value"] for r in results if r["name"] == "Kernel"), "?")

    lines = [
        f"  {'System':<10}Kernel: {kernel:<20}  Secure Boot: {fmt('Secure Boot')}",
        f"  {'Security':<10}ASLR: {fmt('ASLR'):<22}  Lockdown: {fmt('Lockdown')}",
        f"  {'Network':<10}Firewall: {fmt('Firewall'):<18}  Ports: {fmt('Open Ports')}",
        f"  {'Score':<10}{score_bar(score, width=15)}  {score}/100",
    ]

    print()
    width = max(len(_strip_ansi(l)) for l in lines) + 4
    print("  ┌" + "─" * (width - 2) + "┐")
    for l in lines:
        pad = width - len(_strip_ansi(l)) - 2
        print("  │" + l + " " * pad + "│")
    print("  └" + "─" * (width - 2) + "┘")
    print()


# ─────────────────────────────────────────────
#  Short output – Side variant
# ─────────────────────────────────────────────


def _short_side(results: list[dict]) -> None:
    score, _ = calculate_score(results)

    def fmt(name) -> str:
        r = next((x for x in results if x["name"] == name), None)
        if r is None:
            return "N/A"
        return colorize(r["status"], f"{ICONS.get(r['status'], '•')} {r['value']}")

    kernel = next((r["value"] for r in results if r["name"] == "Kernel"), "?")

    info_lines = [
        f"  Kernel       {kernel}",
        f"  Secure Boot  {fmt('Secure Boot')}",
        f"  ASLR         {fmt('ASLR')}",
        f"  Lockdown     {fmt('Lockdown')}",
        f"  Firewall     {fmt('Firewall')}",
        f"  Ports        {fmt('Open Ports')}",
        f"  Score        {score_bar(score, width=12)}  {score}/100",
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


def print_results_short(results: list[dict]) -> None:
    if SHORT_LAYOUT == "side":
        _short_side(results)
    else:
        _short_box(results)
