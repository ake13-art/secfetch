from secfetch.core.scoring import calculate_score

# ─────────────────────────────────────────────
#  Layout selection for --short mode
#
#  Activate one of the two variants by
#  commenting / uncommenting:
#
#  SHORT_LAYOUT = "box"        ← Box with categories (default)
#  SHORT_LAYOUT = "side"       ← Logo left, info right
# ─────────────────────────────────────────────

SHORT_LAYOUT = "box"
# SHORT_LAYOUT = "side"


# ─────────────────────────────────────────────
#  Icons
# ─────────────────────────────────────────────

ICONS = {
    "ok": "✔",
    "warn": "⚠",
    "bad": "✖",
    "info": "•",
}

# ─────────────────────────────────────────────
#  ASCII Logo
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

# ─────────────────────────────────────────────
#  Category titles and display order
# ─────────────────────────────────────────────

CATEGORY_TITLES = {
    "system": "System",
    "kernel_security": "Kernel Security",
    "kernel_hardening": "Kernel Hardening",
    "network": "Network",
}

CATEGORY_ORDER = [
    "system",
    "kernel_security",
    "kernel_hardening",
    "network",
]


# ─────────────────────────────────────────────
#  Score bar
# ─────────────────────────────────────────────


def score_bar(score: int, width: int = 20) -> str:
    """Return a filled progress bar string for the given score."""
    filled = round((score / 100) * width)
    return "█" * filled + "░" * (width - filled)


# ─────────────────────────────────────────────
#  Full output (default mode)
# ─────────────────────────────────────────────


def print_results(results: list[dict]) -> None:
    """Print full categorized security report with logo."""
    print(LOGO_FULL)

    sections: dict[str, list] = {}
    for r in results:
        cat = r.get("category", "misc")
        sections.setdefault(cat, []).append(r)

    for cat in CATEGORY_ORDER:
        if cat not in sections:
            continue

        title = CATEGORY_TITLES.get(cat, cat.replace("_", " ").title())
        print(f"  {title}")
        print("  " + "─" * 40)

        for r in sections[cat]:
            icon = ICONS.get(r["status"], "•")
            name = r["name"].ljust(22)
            print(f"    {name}  {icon}  {r['value']}")

        print()

    score, cat_scores = calculate_score(results)

    print("  Security Score")
    print("  " + "─" * 40)

    for cat in CATEGORY_ORDER:
        if cat not in cat_scores:
            continue
        title = CATEGORY_TITLES.get(cat, cat).ljust(20)
        s = cat_scores[cat]
        b = score_bar(s, width=12)
        print(f"    {title}  {b}  {s}/100")

    print("  " + "─" * 40)
    print(f"    {'Total'.ljust(20)}  {score_bar(score, width=12)}  {score}/100")
    print()


# ─────────────────────────────────────────────
#  Short output – Box variant (default)
# ─────────────────────────────────────────────


def _short_box(results: list[dict]) -> None:
    """Short output – box layout with categories."""
    score, _ = calculate_score(results)
    bar = score_bar(score, width=15)

    def fmt(r) -> str:
        if r is None:
            return "N/A"
        icon = ICONS.get(r["status"], "•")
        return f"{icon} {r['value']}"

    def get(name):
        return next((r for r in results if r["name"] == name), None)

    kernel = next((r["value"] for r in results if r["name"] == "Kernel"), "?")
    sb = fmt(get("Secure Boot"))
    aslr = fmt(get("ASLR"))
    lockdown = fmt(get("Lockdown"))
    fw = fmt(get("Firewall"))
    ports = fmt(get("Open Ports"))

    lines = [
        f"  {'System':<10}Kernel: {kernel:<20}  Secure Boot: {sb}",
        f"  {'Security':<10}ASLR: {aslr:<22}  Lockdown: {lockdown}",
        f"  {'Network':<10}Firewall: {fw:<18}  Ports: {ports}",
        f"  {'Score':<10}{bar}  {score}/100",
    ]

    width = max(len(l) for l in lines) + 2

    title = "Security Status"
    pad = (width - len(title)) // 2
    header = "─" * pad + title + "─" * (width - pad - len(title))

    print(f"  ┌{header}┐")
    for line in lines:
        print(f"  │{line:<{width}}│")
    print(f"  └{'─' * width}┘")
    print()


# ─────────────────────────────────────────────
#  Short output – Side variant
#  Logo on the left, info on the right
# ─────────────────────────────────────────────


def _short_side(results: list[dict]) -> None:
    """Print compact security status with logo on the left side."""
    score, _ = calculate_score(results)
    bar = score_bar(score, width=14)

    kernel = next((r["value"] for r in results if r["name"] == "Kernel"), "?")
    sb = next((r for r in results if r["name"] == "Secure Boot"), None)
    aslr = next((r for r in results if r["name"] == "ASLR"), None)
    fw = next((r for r in results if r["name"] == "Firewall"), None)

    def fmt(r) -> str:
        """Format a single check result as icon + value string."""
        if r is None:
            return "N/A"
        icon = ICONS.get(r["status"], "•")
        return f"{icon} {r['value']}"

    info_lines = [
        f"  {'Kernel':<16}{kernel}",
        f"  {'Secure Boot':<16}{fmt(sb)}",
        f"  {'Firewall':<16}{fmt(fw)}",
        f"  {'ASLR':<16}{fmt(aslr)}",
        f"  {'Score':<16}{bar}  {score}/100",
    ]

    logo_lines = LOGO_SHORT
    max_lines = max(len(logo_lines), len(info_lines))

    for i in range(max_lines):
        left = logo_lines[i] if i < len(logo_lines) else " " * 34
        right = info_lines[i] if i < len(info_lines) else ""
        print(left + right)

    print()


# ─────────────────────────────────────────────
#  Short output – Dispatcher
#  Calls the correct variant based on SHORT_LAYOUT
# ─────────────────────────────────────────────


def print_short(results: list[dict]) -> None:
    """Entry point for --short mode. Layout is controlled by SHORT_LAYOUT."""
    if SHORT_LAYOUT == "side":
        _short_side(results)
    else:
        _short_box(results)
