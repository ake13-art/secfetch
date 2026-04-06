from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="LSM", category="kernel_security", risk="medium")
@handle_check_errors
def check():
    with open("/sys/kernel/security/lsm") as f:
        value = f.read().strip()

    if value:
        return {"status": "ok", "value": value}
    return {"status": "warn", "value": "none"}
