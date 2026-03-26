# checks/network/firewall_rules.py
import subprocess
from secfetch.core.check import security_check


def _ufw_rules():
    # Parse ufw numbered rules
    out = subprocess.run(
        ["ufw", "status", "numbered"], capture_output=True, text=True, timeout=5
    ).stdout
    rules = [l.strip() for l in out.splitlines() if l.strip().startswith("[")]
    return rules


def _iptables_rules():
    # Count non-default iptables rules (skip chain headers and empty lines)
    out = subprocess.run(
        ["iptables", "-L", "-n"], capture_output=True, text=True, timeout=5
    ).stdout
    return [
        l
        for l in out.splitlines()
        if l.strip() and not l.startswith("Chain") and not l.startswith("target")
    ]


def _nft_rules():
    # Count nftables rules (skip comments and table/chain declarations)
    out = subprocess.run(
        ["nft", "list", "ruleset"], capture_output=True, text=True, timeout=5
    ).stdout
    return [
        l
        for l in out.splitlines()
        if l.strip() and not l.startswith("#") and "rule" in l.lower()
    ]


@security_check(name="Firewall Rules", category="network", risk="high")  # BUG FIX: Changed from "low" to "high" - no firewall is critical
def check():
    """
    Check if firewall is active and has rules configured.
    BUG FIX: Improved logic to check firewall status, not just rules.
    BUG FIX: Changed risk level from low to high - missing firewall is critical.
    """
    # First check if ufw is enabled (most common on Ubuntu/Debian)
    try:
        result = subprocess.run(
            ["ufw", "status"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            status_line = result.stdout.split('\n')[0].strip()
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
    
    # BUG FIX: No firewall found is "bad", not "warn" - this is a critical security issue
    return {"status": "bad", "value": "No active firewall found"}
