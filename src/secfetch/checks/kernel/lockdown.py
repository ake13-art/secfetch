from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="Lockdown", category="kernel_security", risk="medium")
@handle_check_errors
def check():
    with open("/sys/kernel/security/lockdown") as f:
        content = f.read().strip()
    for token in content.split():
        if token.startswith("[") and token.endswith("]"):
            mode = token[1:-1]
            if mode in ("confidentiality", "integrity"):
                return {"status": "ok", "value": mode}
            if mode == "none":
                return {"status": "warn", "value": "none"}
    return {"status": "info", "value": "unknown"}
