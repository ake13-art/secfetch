from secfetch.core.check import security_check


def read_sysctl(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


@security_check(name="kptr_restrict", category="kernel_hardening", risk="medium")
def check_kptr():
    val = read_sysctl("/proc/sys/kernel/kptr_restrict")

    if val == "2":
        return {"status": "ok", "value": "Fully Restricted"}
    if val == "1":
        return {"status": "warn", "value": "Partially Restricted"}
    if val == "0":
        return {"status": "bad", "value": "Unrestricted"}

    return {"status": "info", "value": "Unknown"}


@security_check(name="dmesg_restrict", category="kernel_hardening", risk="medium")
def check_dmesg():
    val = read_sysctl("/proc/sys/kernel/dmesg_restrict")

    if val == "1":
        return {"status": "ok", "value": "Enabled"}
    if val == "0":
        return {"status": "bad", "value": "Disabled"}

    return {"status": "info", "value": "Unknown"}


@security_check(name="ptrace_scope", category="kernel_hardening", risk="medium")
def check_ptrace():
    val = read_sysctl("/proc/sys/kernel/yama/ptrace_scope")

    if val == "3":
        return {"status": "ok", "value": "Fully Restricted"}
    if val == "2":
        return {"status": "ok", "value": "Admin Only"}
    if val == "1":
        return {"status": "ok", "value": "Restricted"}
    if val == "0":
        return {"status": "bad", "value": "Unrestricted"}

    return {"status": "info", "value": "Unknown"}


@security_check(name="modules_disabled", category="kernel_hardening", risk="low")
def check_modules():
    val = read_sysctl("/proc/sys/kernel/modules_disabled")

    if val == "1":
        return {"status": "ok", "value": "Enabled"}
    if val == "0":
        return {"status": "warn", "value": "Disabled"}

    return {"status": "info", "value": "Unknown"}


@security_check(name="unprivileged_bpf", category="kernel_hardening", risk="medium")
def check_bpf():
    val = read_sysctl("/proc/sys/kernel/unprivileged_bpf_disabled")

    if val == "2":
        return {"status": "ok", "value": "Permanently Disabled"}
    if val == "1":
        return {"status": "ok", "value": "Disabled"}
    if val == "0":
        return {"status": "bad", "value": "Enabled"}

    return {"status": "info", "value": "Unknown"}
