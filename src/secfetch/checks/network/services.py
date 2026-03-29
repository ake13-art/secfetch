# checks/network/services.py
import subprocess

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors  # ERROR HANDLING FIX

# Services that increase attack surface or are known risks
SUSPICIOUS = {
    "telnetd",
    "rshd",
    "rlogind",
    "ftpd",
    "vsftpd",
    "proftpd",
    "xinetd",
    "inetd",
    "rpcbind",
}

UNNECESSARY = {
    "cups",
    "cups-browsed",
    "bluetooth",
    "geoclue",
    "ModemManager",
    "brltty",
    "avahi-daemon",
}


@security_check(name="Services", category="network", risk="medium")
@handle_check_errors  # ERROR HANDLING FIX: Consistent error handling
def check():
    """Find running services with systemctl and check against blacklists."""
    # ERROR HANDLING FIX: Removed manual exception handling - now handled by decorator
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
            svc = parts[0].replace(".service", "")
            services.append(svc)

    if not services:
        return {"status": "info", "value": "None detected"}

    total = len(services)
    flagged_sus = [s for s in services if s in SUSPICIOUS]
    flagged_unn = [s for s in services if s in UNNECESSARY]

    if flagged_sus:
        names = ", ".join(sorted(flagged_sus))
        return {"status": "bad", "value": f"{total} running, suspicious: {names}"}

    if flagged_unn:
        names = ", ".join(sorted(flagged_unn))
        return {"status": "warn", "value": f"{total} running, unnecessary: {names}"}

    return {"status": "ok", "value": f"{total} running, none flagged"}
