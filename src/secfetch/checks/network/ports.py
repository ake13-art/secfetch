import os

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors, safe_subprocess_run
from secfetch.data import port_db
from secfetch.ui.colors import GREEN, RED, RESET, YELLOW

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
@handle_check_errors
def check() -> dict[str, str]:
    """Check for open network ports and classify by risk level."""
    result = safe_subprocess_run(["ss", "-tulnp"], timeout=5)
    if result.returncode != 0:
        return {"status": "info", "value": "scan unavailable"}
    ports = []
    seen = set()
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
            if not (0 <= port_num <= 65535):
                continue

            key = (port_str, proto)
            if key not in seen:
                seen.add(key)
                name, risk = port_db.get_port_info(port_num)
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
        "unknown": 2,
        "expected": 0,
        "info": 0,
    }
    worst = max(ports, key=lambda p: risk_order.get(p["risk"], 0))
    overall = "warn" if risk_order.get(worst["risk"], 0) >= 2 else "info"
    if worst["risk"] == "suspicious":
        overall = "bad"

    short_mode = os.environ.get("SECFETCH_SHORT", "0") == "1"

    def format_port(p: dict) -> str:
        if short_mode:
            return colorize_port(p["port"], p["risk"])
        return colorize_port(f"{p['port']} ({p['name']}/{p['proto']})", p["risk"])

    value = ", ".join(format_port(p) for p in sorted(ports, key=lambda p: int(p["port"])))

    return {"status": overall, "value": value}
