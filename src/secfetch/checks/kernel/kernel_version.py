import platform

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors  # ERROR HANDLING FIX


# Report running kernel version (informational only)
@security_check(name="Kernel", category="system", risk="info")
@handle_check_errors  # ERROR HANDLING FIX: Added consistent error handling
def check():
    return {"status": "info", "value": platform.release()}
