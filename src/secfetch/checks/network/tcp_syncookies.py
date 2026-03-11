from secfetch.core.check import security_check


# Check SYN flood protection via TCP SYN cookies
@security_check(name="TCP SYN Cookies", category="network", risk="medium")
def check():
    try:
        with open("/proc/sys/net/ipv4/tcp_syncookies") as f:
            val = f.read().strip()
        return {
            "status": "ok" if val == "1" else "bad",
            "value": "Enabled" if val == "1" else "Disabled",
        }
    except OSError:
        return {"status": "info", "value": "Unknown"}
