# checks/network/services.py
from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors, safe_subprocess_run

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
@handle_check_errors
def check():
    """Find running services with systemctl and check against blacklists."""
    result = safe_subprocess_run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend",
        ],
        timeout=5,
    )
    if result.returncode != 0:
        return {"status": "info", "value": "check unavailable"}

    services = []
    out = result.stdout
    for line in out.splitlines():
        parts = line.split()
        if parts:
            svc = parts[0].replace(".service", "")
            services.append(svc)

    if not services:
        return {"status": "info", "value": "None detected"}

    total = len(services)
    suspicious_lower = {s.lower() for s in SUSPICIOUS}
    unnecessary_lower = {s.lower() for s in UNNECESSARY}
    flagged_sus = [s for s in services if s.lower() in suspicious_lower]
    flagged_unn = [s for s in services if s.lower() in unnecessary_lower]

    if flagged_sus:
        names = ", ".join(sorted(flagged_sus))
        return {"status": "bad", "value": f"{total} running, suspicious: {names}"}

    if flagged_unn:
        names = ", ".join(sorted(flagged_unn))
        return {"status": "warn", "value": f"{total} running, unnecessary: {names}"}

    return {"status": "ok", "value": f"{total} running, none flagged"}
