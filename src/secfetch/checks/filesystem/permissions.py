"""Filesystem permission security checks."""
# Note: This module uses subprocess.run directly (not safe_subprocess_run) because
# the find commands require stderr=DEVNULL to suppress "Permission denied" noise
# from /proc, /sys, and other restricted paths during recursive filesystem scans.
import os
import stat
import subprocess
from pathlib import Path

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors

_SAFE_SUID_PATHS: frozenset[str] = frozenset({
    "/usr/bin/sudo", "/bin/su", "/usr/bin/su",
    "/usr/bin/passwd", "/usr/bin/gpasswd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/expiry",
    "/bin/mount", "/usr/bin/mount", "/bin/umount", "/usr/bin/umount",
    "/bin/ping", "/usr/bin/ping", "/bin/ping6", "/usr/bin/ping6",
    "/usr/bin/pkexec", "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
})
_SAFE_SUID_NAMES: frozenset[str] = frozenset(os.path.basename(p) for p in _SAFE_SUID_PATHS)


@security_check(name="World Writable", category="filesystem", risk="high")
@handle_check_errors
def world_writable() -> dict[str, str]:
    """Find world-writable files outside of expected locations."""
    cmd = [
        "find", "/",
        "-type", "f",
        "-perm", "-002",
        "-not", "-path", "/proc/*",
        "-not", "-path", "/sys/*",
        "-not", "-path", "/dev/*",
        "-not", "-path", "/tmp/*",
        "-not", "-path", "/var/tmp/*",
        "-not", "-path", "/run/*",
        "-not", "-path", "/var/run/*",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stderr=subprocess.DEVNULL)
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    if not files:
        return {"status": "ok", "value": "No unexpected world-writable files"}
    elif len(files) <= 5:
        return {"status": "warn", "value": f"{len(files)} world-writable files found"}
    else:
        return {"status": "bad", "value": f"{len(files)} world-writable files found"}


@security_check(name="SUID Binaries", category="filesystem", risk="medium")
@handle_check_errors
def suid_binaries() -> dict[str, str]:
    """Find SUID binaries that could be privilege escalation vectors."""
    cmd = [
        "find", "/",
        "-type", "f",
        "-perm", "-4000",
        "-not", "-path", "/proc/*",
        "-not", "-path", "/sys/*",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stderr=subprocess.DEVNULL)

    total = 0
    unexpected = []

    for line in result.stdout.splitlines():
        if line.strip():
            path = line.strip()
            total += 1
            if path not in _SAFE_SUID_PATHS and os.path.basename(path) not in _SAFE_SUID_NAMES:
                unexpected.append(path)

    unexpected_count = len(unexpected)

    if unexpected_count == 0:
        return {"status": "ok", "value": f"{total} SUID binaries (all expected)"}
    elif unexpected_count <= 3:
        return {"status": "warn", "value": f"{unexpected_count} unexpected SUID binaries"}
    else:
        return {"status": "bad", "value": f"{unexpected_count} unexpected SUID binaries"}


@security_check(name="/tmp noexec", category="filesystem", risk="medium")
@handle_check_errors
def tmp_noexec() -> dict[str, str]:
    """Check if /tmp is mounted with noexec option."""
    with open("/proc/mounts", "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 4 and parts[1] == "/tmp":
                mount_options = parts[3]
                if "noexec" in mount_options:
                    return {"status": "ok", "value": "/tmp mounted with noexec"}
                else:
                    return {"status": "bad", "value": "/tmp allows execution"}

    return {"status": "warn", "value": "/tmp not separately mounted"}


@security_check(name="/tmp Sticky Bit", category="filesystem", risk="low")
@handle_check_errors
def sticky_tmp() -> dict[str, str]:
    """Check if /tmp has the sticky bit set."""
    tmp_path = Path("/tmp")
    if not tmp_path.exists():
        return {"status": "warn", "value": "/tmp directory does not exist"}

    mode = tmp_path.stat().st_mode
    if mode & stat.S_ISVTX:
        return {"status": "ok", "value": "/tmp has sticky bit set"}
    else:
        return {"status": "bad", "value": "/tmp missing sticky bit"}
