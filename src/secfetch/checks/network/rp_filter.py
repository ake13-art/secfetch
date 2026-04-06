from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="Reverse Path Filter", category="network", risk="medium")
@handle_check_errors
def check():
    with open("/proc/sys/net/ipv4/conf/all/rp_filter") as f:
        val = f.read().strip()
    if val == "1":
        return {"status": "ok", "value": "Strict"}
    if val == "2":
        return {"status": "warn", "value": "Loose"}
    return {"status": "bad", "value": "Disabled"}
