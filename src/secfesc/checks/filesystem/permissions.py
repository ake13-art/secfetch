"""Filesystem permission security checks."""
from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

from secfesc.shared.error_handling import handle_check_errors, safe_subprocess_run
from secfesc.shared.registry import security_check

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

_SKIPPED_DIRS = (
    "/proc", "/sys", "/dev", "/tmp", "/var/tmp", "/run", "/var/run",
    "/snap", "/var/lib/docker", "/var/lib/lxc", "/var/lib/containerd",
    "/var/cache", "/var/lib/apt", "/var/lib/dpkg",
)

# Shared cache for the single filesystem traversal, guarded by a lock so
# the parallel check runners (World Writable + SUID Binaries share this
# result) don't race the dict assignment.
_fs_scan_cache: dict[str, list[str]] | None = None
_fs_scan_lock = threading.Lock()


def _build_find_cmd() -> list[str]:
    """Build a find command that prunes known-safe dirs and finds
    world-writable OR suid files in a single traversal."""
    prune_expr = ["("]
    for i, d in enumerate(_SKIPPED_DIRS):
        if i:
            prune_expr.append("-o")
        prune_expr.extend(["-path", d, "-o", "-path", f"{d}/*"])
    prune_expr.append(")")
    return [
        "find", "/", "-xdev", *prune_expr, "-prune", "-o",
        "-type", "f", "(", "-perm", "-0002", "-o", "-perm", "-4000", ")",
        "-printf", "%m %p\n",
    ]


def invalidate_fs_scan_cache() -> None:
    """Drop the cached filesystem scan so the next call re-runs `find`."""
    global _fs_scan_cache
    with _fs_scan_lock:
        _fs_scan_cache = None


def _scan_filesystem() -> tuple[list[str], list[str]]:
    """Run a single find traversal and return (world_writable_files, suid_files).

    Thread-safe via a module-level lock. Returns ([], []) and logs a warning
    if the underlying `find` exits non-zero. Exit code 1 is treated as a
    partial success (some paths unreadable — normal on / due to /proc /sys
    permissions); only returncodes > 1 are fatal.
    """
    global _fs_scan_cache

    with _fs_scan_lock:
        if _fs_scan_cache is not None:
            return (list(_fs_scan_cache["ww"]), list(_fs_scan_cache["suid"]))

        cmd = _build_find_cmd()
        result = safe_subprocess_run(cmd, timeout=30, default="")

        if result.returncode not in (0, 1):
            from secfesc.shared.logger import log_warning
            log_warning(
                f"find exited with code {result.returncode}; "
                "filesystem scan incomplete"
            )
            _fs_scan_cache = {"ww": [], "suid": []}
            return [], []

        ww_files: list[str] = []
        suid_files: list[str] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.strip().split(" ", 1)
            if len(parts) != 2:
                continue
            perm_str, path = parts
            try:
                perm = int(perm_str, 8)
            except ValueError:
                continue
            if perm & stat.S_ISUID:
                suid_files.append(path)
            if perm & stat.S_IWOTH:
                ww_files.append(path)

        _fs_scan_cache = {"ww": ww_files, "suid": suid_files}
        return list(ww_files), list(suid_files)


@security_check(name="World Writable", category="filesystem", risk="high")
@handle_check_errors
def world_writable() -> dict[str, str]:
    """Find world-writable files outside of expected locations."""
    files, _ = _scan_filesystem()

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
    _, suid_files = _scan_filesystem()

    total = 0
    unexpected = []

    for path in suid_files:
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
    try:
        text = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"status": "info", "value": "/proc/mounts not readable"}

    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and parts[1] == "/tmp":
            mount_options = parts[3]
            if "noexec" in mount_options.split(","):
                return {"status": "ok", "value": "/tmp mounted with noexec"}
            else:
                return {"status": "bad", "value": "/tmp allows execution"}

    return {"status": "warn", "value": "/tmp not separately mounted"}


@security_check(name="/tmp Sticky Bit", category="filesystem", risk="low")
@handle_check_errors
def sticky_tmp() -> dict[str, str]:
    """Check if /tmp has the sticky bit set."""
    tmp_path = Path("/tmp")
    try:
        # Use lstat() to avoid following symlinks (TOCTOU protection).
        mode = tmp_path.lstat().st_mode
    except OSError:
        return {"status": "warn", "value": "/tmp directory does not exist"}

    if mode & stat.S_ISVTX:
        return {"status": "ok", "value": "/tmp has sticky bit set"}
    else:
        return {"status": "bad", "value": "/tmp missing sticky bit"}
