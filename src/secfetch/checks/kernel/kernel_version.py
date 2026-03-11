import platform
from secfetch.core.check import security_check


# Report running kernel version (informational only)
@security_check(name="Kernel", category="system", risk="info")
def check():
    return {"status": "info", "value": platform.release()}
