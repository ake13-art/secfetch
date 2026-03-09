import os
import glob
from secfetch.core.check import security_check


@security_check(name="Secure Boot", category="system", risk="medium")
def check():

    # EFI muss überhaupt vorhanden sein
    if not os.path.exists("/sys/firmware/efi"):
        return {"status": "warn", "value": "Not supported (Legacy BIOS)"}

    # SecureBoot Variable auslesen
    pattern = "/sys/firmware/efi/efivars/SecureBoot-*"
    matches = glob.glob(pattern)

    if not matches:
        return {"status": "warn", "value": "EFI var not readable"}

    try:
        with open(matches[0], "rb") as f:
            data = f.read()

        # Byte 4 ist der eigentliche Wert: 1 = aktiv
        if len(data) >= 5 and data[4] == 1:
            return {"status": "ok", "value": "Enabled"}

        return {"status": "bad", "value": "Disabled"}

    except OSError:
        return {"status": "info", "value": "Unknown"}
