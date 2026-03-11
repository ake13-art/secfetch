# checks/network/services.py
import subprocess
from secfetch.core.check import security_check

# Services considered safe / expected on most systems
EXPECTED = {"systemd-resolve", "sshd", "NetworkManager", "systemd-timesyncd"}


@security_check(name="Services", category="network", risk="medium")
def check():
    try:
        # List all active, running services
        out = subprocess.run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-pager",
                "--no-legend",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout

        services = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                # Unit name is first column, strip .service suffix
                svc = parts[0].replace(".service", "")
                services.append(svc)

        if not services:
            return {"status": "info", "value": "None detected"}

        # Flag unexpected services
        unexpected = [s for s in services if s not in EXPECTED]
        total = len(services)

        if not unexpected:
            return {"status": "ok", "value": f"{total} services (all expected)"}
        if len(unexpected) <= 3:
            return {
                "status": "info",
                "value": f"{total} running, review: {', '.join(unexpected[:3])}",
            }
        return {
            "status": "warn",
            "value": f"{total} running, {len(unexpected)} unexpected",
        }

    except Exception as e:
        return {"status": "info", "value": f"Error: {e}"}
