"""Boot loader checks (category: boot).

Focuses on GRUB, the most common Linux boot loader. Verifies that the boot
menu is password-protected (so an attacker at the console cannot edit kernel
parameters to gain a root shell) and that, when a password hash is present, the
config files are not world-readable. Reads only world-readable metadata where
possible; files it cannot read are skipped silently.
"""

from __future__ import annotations

import os

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_read_file

_CAT = "boot"

# GRUB stores the generated menu in one of these; distros differ.
GRUB_CFGS = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
# Hand-edited fragments that may carry the superuser/password directives.
GRUB_SOURCES = [
    "/etc/grub.d/00_header",
    "/etc/grub.d/01_users",
    "/etc/grub.d/40_custom",
    "/boot/grub/user.cfg",
    "/boot/grub2/user.cfg",
]
# Markers that indicate a password is actually configured.
_PASSWORD_MARKERS = ("password_pbkdf2", "set superusers")


def _existing(paths: list[str]) -> list[str]:
    return [p for p in paths if os.path.exists(p)]


def _grub_installed() -> bool:
    return bool(_existing(GRUB_CFGS)) or os.path.isdir("/etc/grub.d")


def _password_files() -> list[str]:
    """Return every readable GRUB file that defines a boot password."""
    hits = []
    for path in _existing(GRUB_CFGS + GRUB_SOURCES):
        content = safe_read_file(path, default=None)
        if content and any(marker in content for marker in _PASSWORD_MARKERS):
            hits.append(path)
    return hits


def _is_world_readable(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & 0o004)
    except OSError:
        return False


@audit_check("boot")
def check_boot() -> list[AuditFinding]:
    if not _grub_installed():
        return []

    findings: list[AuditFinding] = []
    password_files = _password_files()

    if not password_files:
        findings.append(AuditFinding.found(
            _CAT, "BOOT-5122", "GRUB boot menu is not password-protected", "medium",
            "No GRUB password (set superusers / password_pbkdf2) was found. "
            "Anyone at the console can edit boot entries and boot into a root "
            "shell via 'init=/bin/bash'.",
            "Generate a hash with 'grub-mkpasswd-pbkdf2', add a 'set superusers' "
            "and 'password_pbkdf2' entry under /etc/grub.d/, then regenerate "
            "grub.cfg with 'grub-mkconfig -o /boot/grub/grub.cfg'.",
        ))
    else:
        # A password hash is set; make sure it isn't readable by everyone.
        exposed = [p for p in password_files if _is_world_readable(p)]
        if exposed:
            findings.append(AuditFinding.found(
                _CAT, "BOOT-5121", "GRUB password hash is world-readable", "low",
                "GRUB config files containing the boot password hash are "
                "readable by all users, exposing the hash to offline cracking.",
                "Restrict access, e.g. 'sudo chmod o-r <file>'.",
                ", ".join(exposed),
            ))

    return findings
