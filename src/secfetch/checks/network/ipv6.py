from secfetch.core.check import security_check


@security_check(name="IPv6", category="network", risk="low")
def check():
    try:
        # read global ipv6 disable flag
        with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
            val = f.read().strip()
        if val == "1":
            return {"status": "ok", "value": "Disabled"}
        return {"status": "info", "value": "Enabled"}
    except OSError:
        return {"status": "info", "value": "Unknown"}
