"""
Filesystem permission security checks
IMPLEMENTATION FIX: Added missing world-writable and SUID checks promised in config/help
"""
import os
import stat
import subprocess
from pathlib import Path

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors  # ERROR HANDLING FIX


@security_check(name="World Writable", category="filesystem", risk="high")
@handle_check_errors  # ERROR HANDLING FIX
def world_writable():
    """
    Find world-writable files outside of expected locations.
    SECURITY RISK: World-writable files can be modified by any user.
    """
    try:
        # Use find command to locate world-writable files
        # Exclude /proc, /sys, /dev, /tmp and other expected locations
        cmd = [
            "find", "/",
            "-type", "f",
            "-perm", "-002",  # world-writable
            "-not", "-path", "/proc/*",
            "-not", "-path", "/sys/*",
            "-not", "-path", "/dev/*",
            "-not", "-path", "/tmp/*",
            "-not", "-path", "/var/tmp/*",
            "-not", "-path", "/run/*",
            "-not", "-path", "/var/run/*",
            "2>/dev/null"  # Suppress permission denied errors
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # Parse output - each line is a world-writable file
        files = [line.strip() for line in result.stdout.splitlines() if line.strip()]

        if not files:
            return {"status": "ok", "value": "No unexpected world-writable files"}
        elif len(files) <= 5:
            return {"status": "warn", "value": f"{len(files)} world-writable files found"}
        else:
            return {"status": "bad", "value": f"{len(files)} world-writable files found"}

    except subprocess.TimeoutExpired:
        return {"status": "info", "value": "Scan timeout (filesystem too large)"}
    except FileNotFoundError:
        return {"status": "info", "value": "find command not available"}
    except Exception as e:
        return {"status": "info", "value": f"Error: {e}"}


@security_check(name="SUID Binaries", category="filesystem", risk="medium")
@handle_check_errors  # ERROR HANDLING FIX
def suid_binaries():
    """
    Find SUID binaries that could be privilege escalation vectors.
    SECURITY RISK: Unexpected SUID binaries can allow privilege escalation.
    """
    try:
        # Common safe SUID binaries - these are expected
        safe_suid = {
            "sudo", "su", "passwd", "gpasswd", "chsh", "chfn", "newgrp",
            "mount", "umount", "ping", "ping6", "pkexec", "fusermount",
            "dbus-daemon-launch-helper", "polkit-agent-helper-1"
        }

        # Find all SUID files
        cmd = [
            "find", "/",
            "-type", "f",
            "-perm", "-4000",  # SUID bit set
            "2>/dev/null"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        suid_files = []
        unexpected = []

        for line in result.stdout.splitlines():
            if line.strip():
                path = line.strip()
                filename = os.path.basename(path)
                suid_files.append(path)

                if filename not in safe_suid:
                    unexpected.append(path)

        total = len(suid_files)
        unexpected_count = len(unexpected)

        if unexpected_count == 0:
            return {"status": "ok", "value": f"{total} SUID binaries (all expected)"}
        elif unexpected_count <= 3:
            return {"status": "warn", "value": f"{unexpected_count} unexpected SUID binaries"}
        else:
            return {"status": "bad", "value": f"{unexpected_count} unexpected SUID binaries"}

    except subprocess.TimeoutExpired:
        return {"status": "info", "value": "Scan timeout (filesystem too large)"}
    except FileNotFoundError:
        return {"status": "info", "value": "find command not available"}
    except Exception as e:
        return {"status": "info", "value": f"Error: {e}"}


@security_check(name="/tmp noexec", category="filesystem", risk="medium")
def tmp_noexec():
    """
    Check if /tmp is mounted with noexec option.
    SECURITY RISK: Without noexec, attackers can execute binaries from /tmp.
    """
    try:
        # Check /proc/mounts for /tmp mount options
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[1] == "/tmp":
                    mount_options = parts[3]
                    if "noexec" in mount_options:
                        return {"status": "ok", "value": "/tmp mounted with noexec"}
                    else:
                        return {"status": "bad", "value": "/tmp allows execution"}

        # /tmp not separately mounted - check if it's on root filesystem
        # This is usually OK as root filesystem typically has exec
        return {"status": "warn", "value": "/tmp not separately mounted"}

    except FileNotFoundError:
        return {"status": "info", "value": "/proc/mounts not available"}
    except Exception as e:
        return {"status": "info", "value": f"Error: {e}"}


@security_check(name="/tmp Sticky Bit", category="filesystem", risk="low")
def sticky_tmp():
    """
    Check if /tmp has the sticky bit set.
    SECURITY RISK: Without sticky bit, users can delete each other's files in /tmp.
    """
    try:
        # Check if /tmp exists
        tmp_path = Path("/tmp")
        if not tmp_path.exists():
            return {"status": "warn", "value": "/tmp directory does not exist"}

        # Check file mode
        st = tmp_path.stat()
        mode = st.st_mode

        # Check if sticky bit (S_ISVTX) is set
        if mode & stat.S_ISVTX:
            return {"status": "ok", "value": "/tmp has sticky bit set"}
        else:
            return {"status": "bad", "value": "/tmp missing sticky bit"}

    except Exception as e:
        return {"status": "info", "value": f"Error: {e}"}
