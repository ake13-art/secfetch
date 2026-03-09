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

            # Zeilen ohne genug Felder überspringen
            if len(parts) < 5:
                continue

            # Nur LISTEN Zeilen
            if "LISTEN" not in line and "UNCONN" not in line:
                continue

            # Lokale Adresse ist Spalte 4 (index 4)
            local = parts[4]

            # Port extrahieren
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

        value = ", ".join(sorted(ports, key=int))

        # Mehr als 5 offene Ports → warn
        status = "warn" if len(ports) > 5 else "info"

        return {"status": status, "value": value}

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"status": "info", "value": "Unknown"}
