import platform

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="Kernel", category="system", risk="info")
@handle_check_errors
def check():
    return {"status": "info", "value": platform.release()}
