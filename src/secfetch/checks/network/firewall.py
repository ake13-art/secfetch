import subprocess
from secfetch.core.check import security_check


@security_check(name="Firewall", category="network", risk="medium")
def check():
    # try each common firewall backend in order
    for backend, args, keyword in [
        ("ufw", ["ufw", "status"], "active"),
        ("firewalld", ["firewall-cmd", "--state"], "running"),
        ("nftables", ["nft", "list", "ruleset"], ""),
        ("iptables", ["iptables", "-L", "-n", "--line-numbers"], "Chain"),
    ]:
        try:
            out = subprocess.run(
                args, capture_output=True, text=True, timeout=3
            ).stdout.strip()

            if not out:
                continue

            # empty ruleset means nftables is running but not configured
            if backend == "nftables":
                has_rules = any(
                    line.strip()
                    for line in out.splitlines()
                    if not line.startswith("#")
                )
                status = "ok" if has_rules else "warn"
                value = "nftables active" if has_rules else "nftables – no rules"
                return {"status": status, "value": value}

            if keyword.lower() in out.lower():
                return {"status": "ok", "value": f"{backend} active"}

        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return {"status": "bad", "value": "No firewall detected"}
