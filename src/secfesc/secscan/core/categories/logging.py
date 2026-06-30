"""Logging and audit checks (category: logging).

Verifies that a system logger is running, that the kernel audit daemon is
present, and that journald keeps logs across reboots. Uses ``systemctl
is-active`` and world-readable config, so it runs without root; when systemd is
absent the category stays silent.
"""

from __future__ import annotations

import os
import shutil

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_read_file, safe_subprocess_run

_CAT = "logging"

# Any one of these counts as "a system logger is running".
LOGGER_SERVICES = ["systemd-journald", "rsyslog", "syslog-ng"]
JOURNALD_CONF = "/etc/systemd/journald.conf"
JOURNAL_DIR = "/var/log/journal"


def _is_active(service: str) -> bool:
    result = safe_subprocess_run(["systemctl", "is-active", service], timeout=5)
    return result.returncode == 0 and result.stdout.strip() == "active"


def _journald_storage() -> str | None:
    """Return the configured journald Storage= value, or None if unset."""
    for line in safe_read_file(JOURNALD_CONF, default="").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip().lower() == "storage":
            return value.strip().lower()
    return None


@audit_check("logging")
def check_logging() -> list[AuditFinding]:
    if shutil.which("systemctl") is None:
        return []

    findings: list[AuditFinding] = []

    # 1. At least one system logger must be running.
    if not any(_is_active(svc) for svc in LOGGER_SERVICES):
        findings.append(AuditFinding.found(
            _CAT, "LOG-4001", "No active system logging daemon", "high",
            "Neither journald, rsyslog nor syslog-ng is active; security-relevant "
            "events are not being recorded.",
            "Enable a logger, e.g. 'sudo systemctl enable --now systemd-journald'.",
        ))

    # 2. The audit daemon provides a tamper-evident audit trail.
    if not _is_active("auditd"):
        findings.append(AuditFinding.found(
            _CAT, "LOG-4010", "Audit daemon (auditd) is not active", "low",
            "auditd is not running, so there is no kernel-level audit trail of "
            "system calls and security events.",
            "Install and enable auditd: 'sudo systemctl enable --now auditd'.",
        ))

    # 3. journald should persist logs across reboots when it is the active logger.
    if _is_active("systemd-journald"):
        storage = _journald_storage()
        persistent = storage == "persistent" or (
            storage in (None, "auto") and os.path.isdir(JOURNAL_DIR)
        )
        if not persistent:
            findings.append(AuditFinding.found(
                _CAT, "LOG-4031", "journald logs are not persistent", "low",
                "journald is not storing logs persistently; logs are lost on "
                "reboot, hampering incident investigation.",
                "Set 'Storage=persistent' in /etc/systemd/journald.conf (or create "
                "/var/log/journal) and restart systemd-journald.",
                f"Storage={storage or 'auto'}",
            ))

    return findings
