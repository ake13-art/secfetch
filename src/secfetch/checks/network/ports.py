import subprocess
from secfetch.core.check import security_check


@security_check(name="Open Ports", category="network", risk="medium")
def check():
    try:
        result = subprocess.run(
            ["ss", "-tulnp"], capture_output=True, text=True, timeout=5
        )
        ports = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            if "LISTEN" not in line and "UNCONN" not in line:
                continue

            local = parts[4]
            if ":" in local:
                port = local.rsplit(":", 1)[-1]
                try:
                    int(port)
                    if port not in ports:
                        ports.append(port)
                except ValueError:
                    continue

        if not ports:
            return {"status": "ok", "value": "None"}

        # more than 5 open ports is suspicious
        status = "warn" if len(ports) > 5 else "info"
        return {"status": status, "value": ", ".join(sorted(ports, key=int))}

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"status": "info", "value": "Unknown"}
