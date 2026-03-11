from secfetch.core.check import security_check


# Check kernel lockdown mode (integrity/confidentiality/none)
@security_check(name="Lockdown", category="kernel_security", risk="medium")
def check():
    try:
        with open("/sys/kernel/security/lockdown") as f:
            content = f.read().strip()
        # Active mode is wrapped in brackets: [integrity]
        for token in content.split():
            if token.startswith("[") and token.endswith("]"):
                mode = token[1:-1]
                if mode in ("confidentiality", "integrity"):
                    return {"status": "ok", "value": mode}
                if mode == "none":
                    return {"status": "warn", "value": "none"}
        return {"status": "info", "value": "unknown"}
    except OSError:
        return {"status": "info", "value": "not available"}
