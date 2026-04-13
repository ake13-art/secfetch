from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors, sysctl_check

_RP_FILTER = {
    "1": ("ok", "Strict"),
    "2": ("warn", "Loose"),
    "0": ("bad", "Disabled"),
}


@security_check(name="Reverse Path Filter", category="network", risk="medium")
@handle_check_errors
def check() -> dict[str, str]:
    return sysctl_check("/proc/sys/net/ipv4/conf/all/rp_filter", _RP_FILTER)
