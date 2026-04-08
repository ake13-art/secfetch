from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors, safe_read_file

# Map sysctl values to (status, display_value)
_KPTR = {
    "2": ("ok", "Fully Restricted"),
    "1": ("warn", "Partially Restricted"),
    "0": ("bad", "Unrestricted"),
}
_BOOL = {"1": ("ok", "Enabled"), "0": ("bad", "Disabled")}
_BOOL_WARN = {"1": ("ok", "Enabled"), "0": ("warn", "Disabled")}
_PTRACE = {
    "3": ("ok", "Fully Restricted"),
    "2": ("ok", "Admin Only"),
    "1": ("ok", "Restricted"),
    "0": ("bad", "Unrestricted"),
}
_BPF = {
    "2": ("ok", "Permanently Disabled"),
    "1": ("ok", "Disabled"),
    "0": ("bad", "Enabled"),
}


def _sysctl_check(path: str, mapping: dict[str, tuple[str, str]]) -> dict[str, str]:
    """Read a sysctl value from *path* and translate it via *mapping* to a status/value dict."""
    val = safe_read_file(path, default=None)
    if val is not None and val in mapping:
        return {"status": mapping[val][0], "value": mapping[val][1]}
    return {"status": "info", "value": "not available"}


@security_check(name="Kptr Restrict", category="kernel_hardening", risk="medium")
@handle_check_errors
def check_kptr() -> dict[str, str]:
    return _sysctl_check("/proc/sys/kernel/kptr_restrict", _KPTR)


@security_check(name="Dmesg Restrict", category="kernel_hardening", risk="medium")
@handle_check_errors
def check_dmesg() -> dict[str, str]:
    return _sysctl_check("/proc/sys/kernel/dmesg_restrict", _BOOL)


@security_check(name="Ptrace Scope", category="kernel_hardening", risk="medium")
@handle_check_errors
def check_ptrace() -> dict[str, str]:
    return _sysctl_check("/proc/sys/kernel/yama/ptrace_scope", _PTRACE)


@security_check(name="Modules Disabled", category="kernel_hardening", risk="high")
@handle_check_errors
def check_modules() -> dict[str, str]:
    return _sysctl_check("/proc/sys/kernel/modules_disabled", _BOOL)


@security_check(name="Unprivileged BPF", category="kernel_hardening", risk="medium")
@handle_check_errors
def check_bpf() -> dict[str, str]:
    return _sysctl_check("/proc/sys/kernel/unprivileged_bpf_disabled", _BPF)
