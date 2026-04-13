from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import sysctl_check

_ASLR = {
    "2": ("ok", "Full"),
    "1": ("warn", "Partial"),
    "0": ("bad", "Disabled"),
}


@security_check(name="ASLR", category="kernel_security", risk="high")
def check() -> dict[str, str]:
    return sysctl_check("/proc/sys/kernel/randomize_va_space", _ASLR)
