from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import safe_read_file


@security_check(name="IPv6", category="network", risk="low")
def check() -> dict[str, str]:
    val = safe_read_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", default=None)
    if val is None:
        return {"status": "info", "value": "not available"}
    if val == "1":
        return {"status": "ok", "value": "Disabled"}
    return {"status": "info", "value": "Enabled"}
