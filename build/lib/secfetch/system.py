import platform
import glob


def get_kernel_version():
    return platform.release()


def check_secure_boot():
    paths = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")

    if not paths:
        return "Unsupported"

    try:
        with open(paths[0], "rb") as f:
            data = f.read()

        if data[4] == 1:
            return "Enabled"
        return "Disabled"

    except Exception:
        return "Unknown"
