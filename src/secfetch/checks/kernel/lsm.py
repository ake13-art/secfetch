from secfetch.core.check import security_check


@security_check(name="LSM", category="kernel_security", risk="medium")
def check():

    try:
        with open("/sys/kernel/security/lsm") as f:
            value = f.read().strip()

        if value:
            return {"status": "ok", "value": value}

        return {"status": "warn", "value": "none"}

    except OSError:
        return {"status": "info", "value": "not available"}
