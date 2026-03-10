from secfetch.core.check import security_check


@security_check(name="TCP SYN Cookies", category="network", risk="medium")
def check():
    try:
        # syn cookies protect against SYN flood attacks
        with open("/proc/sys/net/ipv4/tcp_syncookies") as f:
            val = f.read().strip()
        if val == "1":
            return {"status": "ok", "value": "Enabled"}
        return {"status": "bad", "value": "Disabled"}
    except OSError:
        return {"status": "info", "value": "Unknown"}
