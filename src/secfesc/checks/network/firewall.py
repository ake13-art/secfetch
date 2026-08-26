# checks/network/firewall.py
from __future__ import annotations

import shutil

from secfesc.shared.error_handling import handle_check_errors, safe_subprocess_run
from secfesc.shared.registry import security_check


def _firewalld_active() -> bool:
    # Use systemctl — no sudo or polkit needed for status queries
    result = safe_subprocess_run(["systemctl", "is-active", "firewalld"], timeout=5)
    return result.returncode == 0 and result.stdout.strip() == "active"


def _ufw_status() -> bool:
    """Check if ufw is active without escalating privileges."""
    result = safe_subprocess_run(["ufw", "status"], timeout=3)
    if result.returncode != 0:
        return False
    return "Status: active" in result.stdout


def _ufw_rules() -> list[str]:
    """Parse ufw numbered rules. Returns empty list on permission/timeout."""
    if not shutil.which("ufw"):
        return []
    result = safe_subprocess_run(["ufw", "status", "numbered"], timeout=3)
    if result.returncode != 0:
        return []
    return [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip().startswith("[")
    ]


def _iptables_rules() -> tuple[str, list[str]]:
    """Probe iptables without sudo.

    Returns (status, rules):
    - status="missing"  → binary not on PATH
    - status="timeout"  → safe_subprocess_run signalled timeout/not-found
    - status="error"    → iptables ran but returned non-zero (likely permission denied)
    - status="empty"    → iptables ran and reported no non-default rules
    - status="ok"       → iptables ran and we found rule lines
    """
    if not shutil.which("iptables"):
        return ("missing", [])
    result = safe_subprocess_run(["iptables", "-L", "-n"], timeout=3)
    if result.returncode == -1:
        return ("timeout", [])
    if result.returncode != 0:
        return ("error", [])
    rules = [
        line
        for line in result.stdout.splitlines()
        if line.strip() and not line.startswith("Chain") and not line.startswith("target")
    ]
    return ("empty" if not rules else "ok", rules)


def _nft_rules() -> tuple[str, list[str]]:
    """Probe nftables without sudo. See ``_iptables_rules`` for return shape."""
    if not shutil.which("nft"):
        return ("missing", [])
    result = safe_subprocess_run(["nft", "list", "ruleset"], timeout=3)
    if result.returncode == -1:
        return ("timeout", [])
    if result.returncode != 0:
        return ("error", [])
    rules = [
        line
        for line in result.stdout.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return ("empty" if not rules else "ok", rules)


@security_check(
    name="Firewall Rules", category="network", risk="high"
)
@handle_check_errors
def check() -> dict[str, str]:
    # firewalld is queryable without sudo.
    if _firewalld_active():
        return {"status": "ok", "value": "firewalld active"}

    # ufw: status without sudo, rules without sudo.
    if shutil.which("ufw") and _ufw_status():
        rules = _ufw_rules()
        return {"status": "ok", "value": f"ufw active: {len(rules)} rules"}

    # nftables / iptables — unprivileged probes only. Returning "ok" requires
    # actual evidence of rules; an empty ruleset means "no firewall" → bad.
    tried_any = False
    for name, fn in [
        ("nftables", _nft_rules),
        ("iptables", _iptables_rules),
    ]:
        status, rules = fn()
        if status == "missing":
            continue
        tried_any = True
        if status == "ok":
            return {"status": "ok", "value": f"{name}: {len(rules)} rules"}
        if status == "empty":
            return {"status": "bad", "value": f"{name} installed but no rules defined"}
        # status in {"timeout", "error"}: try the next backend.

    if not tried_any:
        # No backend present at all — we cannot prove absence of a firewall.
        return {"status": "info", "value": "firewall status unreadable"}

    return {"status": "bad", "value": "No active firewall found"}
