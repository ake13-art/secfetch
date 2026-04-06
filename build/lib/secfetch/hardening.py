from .utils import read_file


def check_kptr_restrict():
    value = read_file("/proc/sys/kernel/kptr_restrict")

    mapping = {"0": "Disabled", "1": "Restricted", "2": "Fully Restricted"}

    return mapping.get(value, "Unknown")


def check_dmesg_restrict():
    value = read_file("/proc/sys/kernel/dmesg_restrict")

    if value == "1":
        return "Enabled"

    if value == "0":
        return "Disabled"

    return "Unknown"


def check_ptrace_scope():
    value = read_file("/proc/sys/kernel/yama/ptrace_scope")

    mapping = {"0": "Classic", "1": "Restricted", "2": "Admin Only", "3": "No Attach"}

    return mapping.get(value, "Unknown")


def check_modules_disabled():
    value = read_file("/proc/sys/kernel/modules_disabled")

    if value == "1":
        return "Disabled"


def check_unprivileged_bpf():
    value = read_file("/proc/sys/kernel/unprivileged_bpf_disabled")

    if value == "1":
        return "Disabled"

    if value == "0":
        return "Enabled"

    return "Unknown"
