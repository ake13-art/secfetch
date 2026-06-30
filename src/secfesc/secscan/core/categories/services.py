"""Service checks (category: services).

Flags enabled systemd units that expose legacy cleartext protocols or are a
common foothold. Uses ``systemctl is-enabled`` (no root required); when
systemd is not present the category stays silent.
"""

from __future__ import annotations

import shutil

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_subprocess_run

_CAT = "services"

# Insecure / legacy units mapped to the protocol or reason they are flagged.
# Both .socket and .service activation styles are covered.
INSECURE_UNITS: dict[str, str] = {
    "telnet.socket": "Telnet transmits credentials in cleartext",
    "telnet.service": "Telnet transmits credentials in cleartext",
    "rsh.socket": "rsh transmits credentials in cleartext",
    "rlogin.socket": "rlogin transmits credentials in cleartext",
    "rexec.socket": "rexec transmits credentials in cleartext",
    "tftp.socket": "TFTP offers unauthenticated file transfer",
    "tftp.service": "TFTP offers unauthenticated file transfer",
    "vsftpd.service": "FTP transmits credentials in cleartext",
    "ypserv.service": "NIS (ypserv) is an outdated, insecure directory service",
    "ypbind.service": "NIS (ypbind) is an outdated, insecure directory service",
    "talk.socket": "talk is an obsolete, unauthenticated service",
    "finger.socket": "finger leaks user account information",
    "rpcbind.socket": "rpcbind exposes RPC services and is a frequent DoS target",
}


def _is_enabled(unit: str) -> bool:
    """True if *unit* is enabled at boot (systemctl is-enabled == enabled)."""
    result = safe_subprocess_run(["systemctl", "is-enabled", unit], timeout=5)
    # is-enabled prints the state and returns 0 only for "enabled"/"enabled-runtime".
    return result.returncode == 0 and result.stdout.strip() in ("enabled", "enabled-runtime")


@audit_check("services")
def check_services() -> list[AuditFinding]:
    if shutil.which("systemctl") is None:
        return []

    enabled = []
    for unit in INSECURE_UNITS:
        if _is_enabled(unit):
            enabled.append(unit)

    if not enabled:
        return []

    reasons = sorted({INSECURE_UNITS[u] for u in enabled})
    return [AuditFinding.found(
        _CAT, "SRV-3104", "Insecure or legacy services are enabled", "high",
        "Enabled units expose insecure/legacy protocols: " + "; ".join(reasons) + ".",
        "Disable each unit you do not need: 'sudo systemctl disable --now <unit>'.",
        ", ".join(sorted(enabled)),
    )]
