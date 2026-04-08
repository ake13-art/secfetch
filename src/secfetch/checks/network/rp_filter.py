from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors, safe_read_file


@security_check(name="Reverse Path Filter", category="network", risk="medium")
@handle_check_errors
def check() -> dict[str, str]:
    val = safe_read_file("/proc/sys/net/ipv4/conf/all/rp_filter", default=None)
    if val is None:
        return {"status": "info", "value": "not available"}
    if val == "1":
        return {"status": "ok", "value": "Strict"}
    if val == "2":
        return {"status": "warn", "value": "Loose"}
    if val == "0":
        return {"status": "bad", "value": "Disabled"}
    return {"status": "info", "value": f"Unknown value: {val}"}
