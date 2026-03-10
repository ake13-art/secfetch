from secfetch.core.check import security_check


@security_check(name="Reverse Path Filter", category="network", risk="medium")
def check():
    try:
        # rp_filter blocks packets with spoofed source addresses
        with open("/proc/sys/net/ipv4/conf/all/rp_filter") as f:
            val = f.read().strip()
        if val == "1":
            return {"status": "ok", "value": "Strict"}
        if val == "2":
            return {"status": "warn", "value": "Loose"}
        return {"status": "bad", "value": "Disabled"}
    except OSError:
        return {"status": "info", "value": "Unknown"}
