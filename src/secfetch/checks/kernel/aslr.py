from secfetch.core.check import security_check


# Check Address Space Layout Randomization level
@security_check(name="ASLR", category="kernel_security", risk="high")
def check():
    try:
        with open("/proc/sys/kernel/randomize_va_space") as f:
            val = f.read().strip()
        # 2 = full, 1 = partial, 0 = disabled
        return {
            "status": {"2": "ok", "1": "warn"}.get(val, "bad"),
            "value": {"2": "Full", "1": "Partial"}.get(val, "Disabled"),
        }
    except OSError:
        return {"status": "info", "value": "Unknown"}
