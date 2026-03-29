# checks/network/firewall_rules.py
import subprocess

from secfetch.core.check import security_check


def _ufw_rules():
    # Parse ufw numbered rules
    out = subprocess.run(
        ["sudo", "ufw", "status", "numbered"], capture_output=True, text=True, timeout=5
    ).stdout
    rules = [line.strip() for line in out.splitlines() if line.strip().startswith("[")]
    return rules


def _iptables_rules():
    # Count non-default iptables rules (skip chain headers and empty lines)
    out = subprocess.run(
        ["sudo", "iptables", "-L", "-n"], capture_output=True, text=True, timeout=5
    ).stdout
    return [
        line
        for line in out.splitlines()
        if line.strip() and not line.startswith("Chain") and not line.startswith("target")
    ]


def _nft_rules():
    # Count nftables rules (skip comments and table/chain declarations)
    out = subprocess.run(
        ["sudo", "nft", "list", "ruleset"], capture_output=True, text=True, timeout=5
    ).stdout
    return [
        line
        for line in out.splitlines()
        if line.strip() and not line.startswith("#") and "rule" in line.lower()
    ]


@security_check(
    name="Firewall Rules", category="network", risk="high"
)  # Changed from "low" to "high" - no firewall is critical
def check():
    # First check if ufw is enabled (most common on Ubuntu/Debian)
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            status_line = result.stdout.split("\n")[0].strip()
            if "Status: active" in status_line:
                # Count actual rules
                rules = _ufw_rules()
                return {"status": "ok", "value": f"ufw active: {len(rules)} rules"}
            else:
                return {"status": "bad", "value": "ufw installed but inactive"}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try other backends - check for any configured rules
    for name, fn in [
        ("nftables", _nft_rules),
        ("iptables", _iptables_rules),
    ]:
        try:
            rules = fn()
            if rules:
                return {"status": "ok", "value": f"{name}: {len(rules)} rules"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # No firewall found is "bad", not "warn" - this is a critical security issue
    return {"status": "bad", "value": "No active firewall found"}
