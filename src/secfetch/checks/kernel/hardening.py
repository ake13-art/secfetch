from secfetch.core.check import security_check


def _read(path):
    # Safely read a sysctl value from /proc or /sys
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


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


def _sysctl_check(path, mapping):
    # Generic sysctl check: read value, look up in mapping
    val = _read(path)
    if val in mapping:
        return {"status": mapping[val][0], "value": mapping[val][1]}
    return {"status": "info", "value": "Unknown"}


# Kernel pointer hiding level (0/1/2)
@security_check(name="kptr_restrict", category="kernel_hardening", risk="medium")
def check_kptr():
    return _sysctl_check("/proc/sys/kernel/kptr_restrict", _KPTR)


# Restrict dmesg access to root
@security_check(name="dmesg_restrict", category="kernel_hardening", risk="medium")
def check_dmesg():
    return _sysctl_check("/proc/sys/kernel/dmesg_restrict", _BOOL)


# Yama ptrace scope (0=open, 3=blocked)
@security_check(name="ptrace_scope", category="kernel_hardening", risk="medium")
def check_ptrace():
    return _sysctl_check("/proc/sys/kernel/yama/ptrace_scope", _PTRACE)


# Prevent loading new kernel modules at runtime
@security_check(name="modules_disabled", category="kernel_hardening", risk="low")
def check_modules():
    return _sysctl_check("/proc/sys/kernel/modules_disabled", _BOOL_WARN)


# Restrict unprivileged BPF usage (0=allowed, 2=permanent)
@security_check(name="unprivileged_bpf", category="kernel_hardening", risk="medium")
def check_bpf():
    return _sysctl_check("/proc/sys/kernel/unprivileged_bpf_disabled", _BPF)
