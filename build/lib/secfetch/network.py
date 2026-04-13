import subprocess
from .utils import read_file


def check_open_ports():
    try:
        result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)

        lines = result.stdout.splitlines()
        ports = set()

        for line in lines[1:]:
            parts = line.split()

            if len(parts) >= 5:
                addr = parts[4]

                if ":" in addr:
                    port = addr.split(":")[-1]
                    if port.isdigit():
                        ports.add(port)

        if not ports:
            return "None"

        return ", ".join(sorted(ports))

    except Exception:
        return "Unknown"


def check_ipv6():
    value = read_file("/proc/sys/net/ipv6/conf/all/disable_ipv6")

    if value == "1":
        return "Disabled"

    if value == "0":
        return "Enabled"

    return "Unknown"
