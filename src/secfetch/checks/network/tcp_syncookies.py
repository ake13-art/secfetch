from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="TCP SYN Cookies", category="network", risk="medium")
@handle_check_errors
def check():
    with open("/proc/sys/net/ipv4/tcp_syncookies") as f:
        val = f.read().strip()
    return {
        "status": "ok" if val == "1" else "bad",
        "value": "Enabled" if val == "1" else "Disabled",
    }
