from __future__ import annotations

import functools
import os
import re
import socket
from datetime import datetime

from secfesc.shared.colors import BLUE, BOLD, CLEAR, GREEN, ICONS, RED, RESET, YELLOW, colorize
from secfesc.shared.scoring import calculate_score
from secfesc.shared.types import CheckResult

# ─────────────────────────────────────────────
#  Short mode layout selector
#  "box"  = categories in a box (default)
#  "side" = logo left, info right
# ─────────────────────────────────────────────
SHORT_LAYOUT = "side"

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
                   ____
   ________  _____/ __/__  __________
  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/
 (__  )  __/ /__/ __/  __(__  ) /__
/____/\___/\___/_/  \___/____/\___/
"""

LOGO_SHORT = [
    r"                   ____",
    r"   ________  _____/ __/__  __________",
    r"  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/",
    r" (__  )  __/ /__/ __/  __(__  ) /__",
    r"/____/\___/\___/_/  \___/____/\___/",
]

# Built-in logos for `secfetch --short`.
# Selected via [display] logo = <name> in checks.conf.
LOGOS: dict[str, list[str]] = {
    "secfesc": LOGO_SHORT,
    # Classic neofetch-style Arch Linux logo — the arch with portal cut-out
    "arch": [
        r"       /\ ",
        r"      /  \ ",
        r"     /\   \ ",
        r"    /  __  \ ",
        r"   /  (  )  \ ",
        r"  / __|  |-- \ ",
        r" /_-''    ''-_\ ",
    ],
    # Neofetch Debian small logo — the swirling D-shape
    "debian": [
        r"  _____ ",
        r" /  __ \ ",
        r"|  /    |",
        r"|  \___-",
        r"-_ ",
        r"  --_ ",
    ],
    # Neofetch Ubuntu small logo — the three circles (circle of friends)
    "ubuntu": [
        r"         _ ",
        r"     ---(_)",
        r" _/  ---  \ ",
        r"(_) |   | ",
        r"  \  --- _/ ",
        r"     ---(_) ",
    ],
    # Fedora hat shape — the distro is literally named after this hat
    "fedora": [
        r"      ___ ",
        r"    /     \ ",
        r"   /  , ,  \ ",
        r"  /         \ ",
        r" |___________| ",
        r"",
    ],
    "none": [],
}


def _get_logo_lines() -> list[str]:
    from secfesc.shared.config import load_config
    name = load_config().get("display", "logo", fallback="secfesc").lower().strip()
    return LOGOS.get(name, LOGO_SHORT)


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
    score, cat_scores, unavailable = calculate_score(results)

    print(LOGO_FULL)

    if unavailable:
        print(
            f"  {YELLOW}⚠  {unavailable} check(s) could not be run on this system "
            f"(tool missing or permission denied) — score is therefore a lower bound.{RESET}"
        )
        print()

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
    stamp = datetime.now().strftime("%H:%M:%S")
    print(
        f"  Refreshing every {interval}s  —  Data as of {stamp}  —  Press Q to stop"
    )


# ─────────────────────────────────────────────
#  Short output – Box variant
# ─────────────────────────────────────────────


def _short_box(results: list[CheckResult]) -> None:
    score, _, _ = calculate_score(results)
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
#  Short output – Side variant (fastfetch-style)
# ─────────────────────────────────────────────

_LOGO_GAP = "  "  # gap between logo column and info column
_LBL_W = 11       # widest label: "Secure Boot"


def _short_side(results: list[CheckResult]) -> None:
    score, _, _ = calculate_score(results)
    fmt = functools.partial(_format_check_result, results)
    kernel = next((r["value"] for r in results if r["name"] == "Kernel"), "?")

    try:
        user = os.getenv("USER") or os.getenv("LOGNAME") or "user"
        host = socket.gethostname()
    except Exception:  # pragma: no cover
        user, host = "user", "host"

    userhost = f"{user}@{host}"

    def _row(label: str, value: str) -> str:
        return f"  {BLUE}{label.ljust(_LBL_W)}{RESET}  {value}"

    info_lines: list[str] = [
        f"  {BOLD}{BLUE}{userhost}{RESET}",
        f"  {BLUE}{'─' * len(userhost)}{RESET}",
        _row("Kernel", kernel),
        _row("Secure Boot", fmt("Secure Boot")),
        _row("ASLR", fmt("ASLR")),
        _row("Lockdown", fmt("Lockdown")),
        _row("Firewall", fmt("Firewall Rules")),
        _row("Ports", fmt("Open Ports")),
        _row("Score", f"{score_bar(score, width=_SCORE_BAR_WIDTH_FULL)}  {score}/100"),
    ]

    logo = _get_logo_lines()

    print()
    if not logo:
        for line in info_lines:
            print(line)
        print()
        return

    col = max(len(line) for line in logo)
    n = max(len(logo), len(info_lines))
    for i in range(n):
        logo_text = logo[i] if i < len(logo) else ""
        left = f"{BOLD}{BLUE}{logo_text.ljust(col)}{RESET}{_LOGO_GAP}"
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
