"""Filesystem permission security checks."""
import os
import stat
import subprocess
from pathlib import Path

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="World Writable", category="filesystem", risk="high")
@handle_check_errors
def world_writable():
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
def suid_binaries():
    """Find SUID binaries that could be privilege escalation vectors."""
    safe_suid = {
        "sudo", "su", "passwd", "gpasswd", "chsh", "chfn", "newgrp",
        "mount", "umount", "ping", "ping6", "pkexec", "fusermount",
        "dbus-daemon-launch-helper", "polkit-agent-helper-1"
    }

    cmd = [
        "find", "/",
        "-type", "f",
        "-perm", "-4000",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stderr=subprocess.DEVNULL)

    total = 0
    unexpected = []

    for line in result.stdout.splitlines():
        if line.strip():
            path = line.strip()
            filename = os.path.basename(path)
            total += 1
            if filename not in safe_suid:
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
def tmp_noexec():
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
def sticky_tmp():
    """Check if /tmp has the sticky bit set."""
    tmp_path = Path("/tmp")
    if not tmp_path.exists():
        return {"status": "warn", "value": "/tmp directory does not exist"}

    mode = tmp_path.stat().st_mode
    if mode & stat.S_ISVTX:
        return {"status": "ok", "value": "/tmp has sticky bit set"}
    else:
        return {"status": "bad", "value": "/tmp missing sticky bit"}
