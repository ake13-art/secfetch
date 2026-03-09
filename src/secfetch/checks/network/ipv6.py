import subprocess
from secfetch.core.check import security_check


@security_check(name="IPv6", category="network", risk="low")
def check():

    try:
        with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
            val = f.read().strip()

        if val == "1":
            return {"status": "info", "value": "Disabled"}

        return {"status": "info", "value": "Enabled"}

    except OSError:
        return {"status": "info", "value": "Unknown"}
