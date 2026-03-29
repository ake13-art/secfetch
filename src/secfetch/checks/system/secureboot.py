import glob
import os

from secfetch.core.check import security_check


# Check UEFI Secure Boot status via efivars
@security_check(name="Secure Boot", category="system", risk="medium")
def check():
    # Secure Boot requires EFI firmware
    if not os.path.exists("/sys/firmware/efi"):
        return {"status": "warn", "value": "Not supported (Legacy BIOS)"}
    matches = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    if not matches:
        return {"status": "warn", "value": "EFI var not readable"}
    try:
        with open(matches[0], "rb") as f:
            data = f.read()
        # Byte 4 holds the value: 1 = enabled
        if len(data) >= 5 and data[4] == 1:
            return {"status": "ok", "value": "Enabled"}
        return {"status": "bad", "value": "Disabled"}
    except OSError:
        return {"status": "info", "value": "Unknown"}
