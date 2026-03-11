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


@security_check(name="Firewall Rules", category="network", risk="low")
def check():
    # Try each backend, report rule count
    for name, fn in [
        ("ufw", _ufw_rules),
        ("nftables", _nft_rules),
        ("iptables", _iptables_rules),
    ]:
        try:
            rules = fn()
            if rules:
                return {"status": "ok", "value": f"{name}: {len(rules)} rules"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return {"status": "warn", "value": "No rules found"}
