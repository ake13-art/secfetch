import subprocess
from secfetch.core.check import security_check


@security_check(name="Firewall", category="network", risk="medium")
def check():

    try:
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True)

        if "active" in result.stdout.lower():
            return {"status": "ok", "value": "Active"}

        return {"status": "bad", "value": "Inactive"}

    except Exception:
        return {"status": "info", "value": "Unknown"}
