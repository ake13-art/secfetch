from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="ASLR", category="kernel_security", risk="high")
@handle_check_errors
def check():
    with open("/proc/sys/kernel/randomize_va_space") as f:
        val = f.read().strip()
    return {
        "status": {"2": "ok", "1": "warn"}.get(val, "bad"),
        "value": {"2": "Full", "1": "Partial"}.get(val, "Disabled"),
    }
