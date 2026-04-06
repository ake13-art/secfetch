from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="IPv6", category="network", risk="low")
@handle_check_errors
def check():
    with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
        val = f.read().strip()
    if val == "1":
        return {"status": "ok", "value": "Disabled"}
    return {"status": "info", "value": "Enabled"}
