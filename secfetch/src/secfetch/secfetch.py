import platform


def get_kernel():
    return platform.release()


def get_aslr():
    with open("/proc/sys/kernel/randomize_va_space") as f:
        value = f.read().strip()

    mapping = {"0": "Disabled", "1": "Partial", "2": "Full"}

    return mapping.get(value, "Unknown")
