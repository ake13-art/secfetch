import os
import glob
from secfetch.core.check import security_check


@security_check(name="Secure Boot", category="system", risk="medium")
def check():
    # secure boot requires EFI – skip on legacy BIOS
    if not os.path.exists("/sys/firmware/efi"):
        return {"status": "warn", "value": "Not supported (Legacy BIOS)"}

    matches = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    if not matches:
        return {"status": "warn", "value": "EFI var not readable"}

    try:
        with open(matches[0], "rb") as f:
            data = f.read()
        # byte 4 holds the actual value: 1 = enabled
        if len(data) >= 5 and data[4] == 1:
            return {"status": "ok", "value": "Enabled"}
        return {"status": "bad", "value": "Disabled"}
    except OSError:
        return {"status": "info", "value": "Unknown"}
