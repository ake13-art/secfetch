from __future__ import annotations

import os
import re

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors, safe_subprocess_run
from secfetch.core.types import PortEntry
from secfetch.data import port_db
from secfetch.ui.colors import GREEN, RED, RESET, YELLOW

RISK_COLORS = {
    "expected": GREEN,
    "unknown": YELLOW,
    "unnecessary": YELLOW,
    "suspicious": RED,
}

# Risk priority values — higher means greater concern
_RISK_PRIORITY: dict[str, int] = {
    "suspicious": 3,
    "unnecessary": 2,
    "unknown": 2,
    "expected": 0,
    "info": 0,
}
_RISK_THRESHOLD_BAD = 3
_RISK_THRESHOLD_WARN = 2

# Matches port from ss local-address: handles IPv4, IPv6 brackets, and scope IDs
_PORT_RE = re.compile(r"(?:\[.*\]|[^:]+):(\d+)$")


def _extract_port(local: str) -> str | None:
    """Extract port string from ss local-address field."""
    m = _PORT_RE.search(local)
    return m.group(1) if m else None


def colorize_port(port_str: str, risk: str) -> str:
    color = RISK_COLORS.get(risk, YELLOW)
    return f"{color}{port_str}{RESET}"


def _parse_ports(stdout: str) -> list[PortEntry]:
    """Parse ss -tulnp output into a deduplicated list of PortEntry dicts."""
    ports: list[PortEntry] = []
    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or ("LISTEN" not in line and "UNCONN" not in line):
            continue
        local = parts[4]
        proto = "UDP" if "udp" in line.lower() else "TCP"
        port_str = _extract_port(local)
        if port_str is None:
            continue
        try:
            port_num = int(port_str)
        except ValueError:
            continue
        if not (0 <= port_num <= 65535):
            continue
        key = (port_str, proto)
        if key not in seen:
            seen.add(key)
            name, risk = port_db.get_port_info(port_num)
            ports.append({"port": port_str, "name": name, "proto": proto, "risk": risk})
    return ports


@security_check(name="Open Ports", category="network", risk="medium")
@handle_check_errors
def check() -> dict[str, str]:
    """Check for open network ports and classify by risk level."""
    result = safe_subprocess_run(["ss", "-tulnp"], timeout=5)
    if result.returncode != 0:
        return {"status": "info", "value": "scan unavailable"}

    ports = _parse_ports(result.stdout)
    if not ports:
        return {"status": "ok", "value": "None"}

    worst = max(ports, key=lambda p: _RISK_PRIORITY.get(p["risk"], 0))
    priority = _RISK_PRIORITY.get(worst["risk"], 0)
    if priority >= _RISK_THRESHOLD_BAD:
        overall = "bad"
    elif priority >= _RISK_THRESHOLD_WARN:
        overall = "warn"
    else:
        overall = "info"

    short_mode = os.environ.get("SECFETCH_SHORT", "0") == "1"

    def format_port(p: PortEntry) -> str:
        if short_mode:
            return colorize_port(p["port"], p["risk"])
        return colorize_port(f"{p['port']} ({p['name']}/{p['proto']})", p["risk"])

    value = ", ".join(format_port(p) for p in sorted(ports, key=lambda p: int(p["port"])))
    return {"status": overall, "value": value}
