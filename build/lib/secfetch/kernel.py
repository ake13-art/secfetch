from .utils import read_file


def check_aslr():
    value = read_file("/proc/sys/kernel/randomize_va_space")

    mapping = {"0": "Disabled", "1": "Partial", "2": "Full"}

    return mapping.get(value, "Unknown")


def check_lockdown():
    value = read_file("/sys/kernel/security/lockdown")

    if not value:
        return "Unsupported"

    if "[" in value:
        return value.split("[")[1].split("]")[0]

    return value


def check_lsm():
    value = read_file("/sys/kernel/security/lsm")

    if not value:
        return "Unknown"

    return value.replace(",", ", ")
