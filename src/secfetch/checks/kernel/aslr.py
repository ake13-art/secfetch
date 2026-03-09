from secfetch.core.check import security_check


@security_check(name="ASLR", category="kernel_security", risk="high")
def check():

    try:
        with open("/proc/sys/kernel/randomize_va_space") as f:
            value = f.read().strip()

        if value == "2":
            return {"status": "ok", "value": "Full"}

        if value == "1":
            return {"status": "warn", "value": "Partial"}

        return {"status": "bad", "value": "Disabled"}

    except OSError:
        return {"status": "info", "value": "Unknown"}

