from __future__ import annotations

import glob
import os

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="Secure Boot", category="system", risk="high")
@handle_check_errors
def check() -> dict[str, str]:
    if not os.path.exists("/sys/firmware/efi"):
        return {"status": "warn", "value": "Not supported (Legacy BIOS)"}
    matches = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    if not matches:
        return {"status": "warn", "value": "EFI var not readable"}
    with open(matches[0], "rb") as f:
        data = f.read()
    # UEFI variable format: 4-byte EFI attributes header + 1-byte value
    if len(data) >= 5 and data[4] == 1:
        return {"status": "ok", "value": "Enabled"}
    return {"status": "bad", "value": "Disabled"}
