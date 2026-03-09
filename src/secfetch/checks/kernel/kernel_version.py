import platform
from secfetch.core.check import security_check


@security_check(name="Kernel", category="system", risk="info")
def check():

    return {"status": "info", "value": platform.release()}
