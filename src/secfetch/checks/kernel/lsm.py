from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import safe_read_file


@security_check(name="LSM", category="kernel_security", risk="high")
def check() -> dict[str, str]:
    value = safe_read_file("/sys/kernel/security/lsm", default=None)
    if value is None:
        return {"status": "info", "value": "not available"}
    if value:
        return {"status": "ok", "value": value}
    return {"status": "warn", "value": "none"}
