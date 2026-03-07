from pathlib import Path
import glob


# Showing the actual randomization
def get_aslr():
    path = Path("/proc/sys/kernel/randomize_va_space")

    try:
        value = path.read_text().strip()
    except FileNotFoundError:
        return "Unknown"

    mapping = {"0": "Disabled", "1": "Partial", "2": "Full"}

    return mapping.get(value, "Unknown")


# Setup Secureboot Check
def check_secure_boot():
    import glob

    paths = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")

    if not paths:
        return "Unsupported"

    with open(paths[0], "rb") as f:
        data = f.read()

    if data[4] == 1:
        return "Enabled"

    return "Disabled"
