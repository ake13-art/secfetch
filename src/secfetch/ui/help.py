from secfetch.ui.output import LOGO_FULL

CHECK_DESCRIPTIONS = {
    "kernel": {
        "title": "Kernel Version",
        "category": "System",
        "risk": "Info",
        "description": "Displays the currently running kernel version.",
        "good": "Up-to-date kernel with recent security patches applied.",
        "bad": "Outdated kernels may contain unpatched CVEs.",
        "fix": "Update your kernel: sudo pacman -Syu",
    },
    "secure boot": {
        "title": "Secure Boot",
        "category": "System",
        "risk": "Medium",
        "description": "Checks whether Secure Boot is enabled. Prevents unsigned bootloaders from running.",
        "good": "Secure Boot is active.",
        "bad": "Disabled Secure Boot allows unsigned bootloaders (Evil Maid attacks).",
        "fix": "Enable Secure Boot in your UEFI firmware settings.",
    },
    "aslr": {
        "title": "ASLR – Address Space Layout Randomization",
        "category": "Kernel Security",
        "risk": "High",
        "description": "Randomizes memory addresses to make memory-based exploits harder.",
        "good": "Value 2 = full randomization active.",
        "bad": "Value 0/1 = attackers can predict memory layout.",
        "fix": "echo 2 | sudo tee /proc/sys/kernel/randomize_va_space",
    },
    "lockdown": {
        "title": "Kernel Lockdown",
        "category": "Kernel Security",
        "risk": "Medium",
        "description": "Restricts userspace access to kernel internals (integrity/confidentiality modes).",
        "good": "integrity or confidentiality mode active.",
        "bad": "none = no restrictions, kernel manipulation possible.",
        "fix": "Add boot parameters: lsm=lockdown lockdown=integrity",
    },
    "kptr_restrict": {
        "title": "kptr_restrict",
        "category": "Kernel Hardening",
        "risk": "Medium",
        "description": "Hides kernel pointers from unprivileged users.",
        "good": "Value 2 = fully hidden.",
        "bad": "Value 0 = pointers exposed, eases kernel exploits.",
        "fix": "echo 2 | sudo tee /proc/sys/kernel/kptr_restrict",
    },
    "dmesg_restrict": {
        "title": "dmesg_restrict",
        "category": "Kernel Hardening",
        "risk": "Medium",
        "description": "Prevents unprivileged users from reading kernel log messages.",
        "good": "Value 1 = only root can read dmesg.",
        "bad": "Value 0 = kernel logs publicly readable.",
        "fix": "echo 1 | sudo tee /proc/sys/kernel/dmesg_restrict",
    },
    "ptrace_scope": {
        "title": "ptrace_scope",
        "category": "Kernel Hardening",
        "risk": "Medium",
        "description": "Limits which processes are allowed to trace other processes.",
        "good": "Value 1–3 = restricted ptrace.",
        "bad": "Value 0 = any process can debug any other process.",
        "fix": "echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope",
    },
    "modules_disabled": {
        "title": "modules_disabled",
        "category": "Kernel Hardening",
        "risk": "Low",
        "description": "Prevents loading of additional kernel modules after boot.",
        "good": "Value 1 = no new modules can be loaded.",
        "bad": "Value 0 = rootkits can be loaded as kernel modules.",
        "fix": "echo 1 | sudo tee /proc/sys/kernel/modules_disabled",
    },
    "unprivileged_bpf": {
        "title": "unprivileged_bpf",
        "category": "Kernel Hardening",
        "risk": "Medium",
        "description": "Prevents unprivileged users from loading BPF programs.",
        "good": "Value 2 = permanently disabled.",
        "bad": "Value 0 = BPF accessible to all users, known exploit vector.",
        "fix": "echo 2 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled",
    },
    "firewall": {
        "title": "Firewall",
        "category": "Network",
        "risk": "Medium",
        "description": "Checks whether UFW is active.",
        "good": "Firewall active = incoming connections are filtered.",
        "bad": "No firewall = all ports reachable.",
        "fix": "sudo ufw enable",
    },
    "lsm": {
        "title": "Linux Security Modules",
        "category": "Kernel Security",
        "risk": "Medium",
        "description": "Shows which Linux Security Modules are active (e.g. AppArmor, SELinux).",
        "good": "One or more LSMs active, e.g. AppArmor or SELinux.",
        "bad": "No LSM active = no mandatory access control enforced.",
        "fix": "Enable AppArmor: add 'apparmor=1 security=apparmor' to your kernel boot parameters.",
    },
    "ipv6": {
        "title": "IPv6",
        "category": "Network",
        "risk": "Low",
        "description": "Shows whether IPv6 is enabled.",
        "good": "Disabled if not needed.",
        "bad": "Active without firewall rules may increase attack surface.",
        "fix": "echo 1 | sudo tee /proc/sys/net/ipv6/conf/all/disable_ipv6",
    },
    "open ports": {
        "title": "Open Ports",
        "category": "Network",
        "risk": "Medium",
        "description": "Lists all locally listening ports.",
        "good": "As few open ports as possible.",
        "bad": "Many open ports = larger attack surface.",
        "fix": "Disable unused services: sudo systemctl disable <service>",
    },
}


def _divider():
    print("  " + "─" * 40)


def print_help() -> None:
    print(LOGO_FULL)
    print("  Usage")
    _divider()
    print("    secfetch              Full security overview")
    print("    secfetch --short      Compact one-box summary")
    print("    secfetch help         This help page")
    print("    secfetch help <check> Detailed info about a check")
    print()
    print("  Available Checks")
    _divider()
    for key, info in CHECK_DESCRIPTIONS.items():
        cat = info["category"]
        title = info["title"]
        print(f"    {key:<20}  {cat:<20}  {title}")
    print()


def print_check_help(name: str) -> None:
    key = name.lower()
    info = CHECK_DESCRIPTIONS.get(key)

    if not info:
        print(f"\n  [!] Unknown check: '{name}'")
        print(f"  Run 'secfetch help' to see all available checks.\n")
        return

    print()
    print(f"  {info['title']}")
    _divider()
    print(f"    Category    {info['category']}")
    print(f"    Risk        {info['risk']}")
    print()
    print(f"    {info['description']}")
    print()
    print(f"  ✔  Good state")
    print(f"    {info['good']}")
    print()
    print(f"  ✖  Bad state")
    print(f"    {info['bad']}")
    print()
    print(f"  Fix")
    _divider()
    print(f"    {info['fix']}")
    print()
