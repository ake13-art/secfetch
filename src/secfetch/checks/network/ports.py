import os
import subprocess

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors  # ERROR HANDLING FIX
from secfetch.data import port_db

RED, YELLOW, GREEN, RESET = "\033[31m", "\033[33m", "\033[32m", "\033[0m"

RISK_COLORS = {
    "expected": GREEN,
    "unknown": YELLOW,
    "unnecessary": YELLOW,
    "suspicious": RED,
}


def colorize_port(port_str: str, risk: str) -> str:
    color = RISK_COLORS.get(risk, YELLOW)
    return f"{color}{port_str}{RESET}"


@security_check(name="Open Ports", category="network", risk="medium")
@handle_check_errors  # ERROR HANDLING FIX: Consistent error handling
def check():
    """Check for open network ports and classify by risk level."""
    # ERROR HANDLING FIX: Removed manual exception handling - now handled by decorator
    result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=5)
    ports = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        if "LISTEN" not in line and "UNCONN" not in line:
            continue

        local = parts[4]
        proto = "UDP" if "udp" in line.lower() else "TCP"

        if ":" in local:
            port_str = local.rsplit(":", 1)[-1]
            try:
                port_num = int(port_str)
            except ValueError:
                continue

            key = (port_str, proto)
            if key not in [(p["port"], p["proto"]) for p in ports]:
                name, risk = port_db.get_port_info(port_num, proto)
                ports.append(
                    {
                        "port": port_str,
                        "name": name,
                        "proto": proto,
                        "risk": risk,
                    }
                )

    if not ports:
        return {"status": "ok", "value": "None"}

    risk_order = {
        "suspicious": 3,
        "unnecessary": 2,
        "warn": 1,
        "unknown": 1,
        "expected": 0,
        "info": 0,
    }
    worst = max(ports, key=lambda p: risk_order.get(p["risk"], 0))
    overall = "warn" if risk_order.get(worst["risk"], 0) >= 2 else "info"
    # ERROR HANDLING FIX: Use standard status values - changed "critical" to "bad"
    if worst["risk"] == "suspicious":
        overall = "bad"

    short_mode = os.environ.get("SECFETCH_SHORT", "0") == "1"

    def format_port(p: dict) -> str:
        if short_mode:
            return colorize_port(p["port"], p["risk"])
        return colorize_port(f"{p['port']} ({p['name']}/{p['proto']})", p["risk"])

    value = ", ".join(format_port(p) for p in sorted(ports, key=lambda p: int(p["port"])))

    return {"status": overall, "value": value}
