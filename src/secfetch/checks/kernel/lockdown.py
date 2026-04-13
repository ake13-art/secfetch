from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import safe_read_file


@security_check(name="Lockdown", category="kernel_security", risk="medium")
def check() -> dict[str, str]:
    content = safe_read_file("/sys/kernel/security/lockdown", default=None)
    if content is None:
        return {"status": "info", "value": "not available"}
    for token in content.split():
        if token.startswith("[") and token.endswith("]"):
            mode = token[1:-1]
            if mode in ("confidentiality", "integrity"):
                return {"status": "ok", "value": mode}
            if mode == "none":
                return {"status": "warn", "value": "none"}
    return {"status": "info", "value": "unknown"}
