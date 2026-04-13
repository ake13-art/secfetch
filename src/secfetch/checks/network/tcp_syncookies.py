from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import sysctl_check

_TCP_SYN = {
    "1": ("ok", "Enabled"),
    "0": ("bad", "Disabled"),
}


@security_check(name="TCP SYN Cookies", category="network", risk="medium")
def check() -> dict[str, str]:
    return sysctl_check("/proc/sys/net/ipv4/tcp_syncookies", _TCP_SYN)
