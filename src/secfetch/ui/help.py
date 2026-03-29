from secfetch.core.logger import log_warning  # PROFESSIONALIZATION FIX: Added proper logging
from secfetch.ui.output import LOGO_FULL

CHECK_DESCRIPTIONS = {
    "kernel": {
        "title": "Kernel Version",
        "category": "System",
        "risk": "Info",
        "description": "Shows the running kernel version.",
        "good": "Up-to-date kernel.",
        "bad": "Outdated kernels may contain known vulnerabilities.",
        "fix": "Update your kernel via your package manager.",
    },
    "secure_boot": {
        "title": "Secure Boot",
        "category": "System",
        "risk": "High",
        "description": "Checks whether UEFI Secure Boot is enabled.",
        "good": "Secure Boot enabled – only signed bootloaders/kernels can run.",
        "bad": "Disabled – bootkits and unsigned code can load at boot.",
        "fix": "Enable Secure Boot in your UEFI/BIOS settings.",
    },
    "aslr": {
        "title": "ASLR",
        "category": "Kernel Security",
        "risk": "High",
        "description": "Address Space Layout Randomization randomizes memory layout to prevent exploits.",
        "good": "Value 2 = full randomization.",
        "bad": "Value 0 or 1 = partial or no randomization.",
        "fix": "echo 2 | sudo tee /proc/sys/kernel/randomize_va_space",
    },
    "lockdown": {
        "title": "Lockdown",
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
        "risk": "High",
        "description": "Prevents loading of new kernel modules at runtime.",
        "good": "Value 1 = module loading blocked (irreversible until reboot).",
        "bad": "Value 0 = modules can be loaded, rootkits possible.",
        "fix": "echo 1 | sudo tee /proc/sys/kernel/modules_disabled  (irreversible!)",
    },
    "unprivileged_bpf": {
        "title": "Unprivileged BPF",
        "category": "Kernel Hardening",
        "risk": "Medium",
        "description": "Controls whether unprivileged users can use BPF programs.",
        "good": "Value 2 = disabled for unprivileged users.",
        "bad": "Value 0 = BPF accessible to all, enables kernel-level attacks.",
        "fix": "echo 2 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled",
    },
    "lsm": {
        "title": "Linux Security Modules",
        "category": "Kernel Security",
        "risk": "High",
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
    "open_ports": {
        "title": "Open Ports",
        "category": "Network",
        "risk": "Medium",
        "description": "Lists all locally listening ports.",
        "good": "As few open ports as possible.",
        "bad": "Many open ports = larger attack surface.",
        "fix": "Review open ports with: ss -tulnp | List services: systemctl list-units --type=service --state=running | Disable unused: sudo systemctl disable --now <service>",
    },
    "firewall": {
        "title": "Firewall",
        "category": "Network",
        "risk": "High",
        "description": "Checks whether ufw, firewalld, or iptables rules are active.",
        "good": "Firewall active with configured rules.",
        "bad": "No firewall found or inactive – traffic is unfiltered.",
        "fix": "Install ufw: sudo apt install ufw && sudo ufw default deny incoming && sudo ufw enable",
    },
    "firewall_rules": {
        "title": "Firewall Rules",
        "category": "Network",
        "risk": "High",
        "description": "Checks active firewall rule count for ufw, nftables and iptables.",
        "good": "Firewall active with configured rules.",
        "bad": "No active firewall or no rules configured.",
        "fix": "Enable ufw: sudo ufw enable && sudo ufw default deny incoming",
    },
    "services": {
        "title": "Active Services",
        "category": "Network",
        "risk": "Medium",
        "description": "Lists running systemd services and flags suspicious or unnecessary ones.",
        "good": "No suspicious or unnecessary services running.",
        "bad": "Suspicious services (e.g. telnetd, rshd) or unnecessary services (e.g. cups, avahi) detected.",
        "fix": "List running services: systemctl list-units --type=service --state=running | Disable unused: sudo systemctl disable --now <service>",
    },
    "tcp_syn_cookies": {
        "title": "TCP SYN Cookies",
        "category": "Network",
        "risk": "Medium",
        "description": "Protects against SYN flood denial-of-service attacks.",
        "good": "Enabled (value 1).",
        "bad": "Disabled = vulnerable to SYN flood attacks.",
        "fix": "sysctl -w net.ipv4.tcp_syncookies=1",
    },
    "reverse_path_filter": {
        "title": "Reverse Path Filter",
        "category": "Network",
        "risk": "Medium",
        "description": "Validates source addresses of incoming packets to prevent IP spoofing.",
        "good": "Enabled (value 1 = strict).",
        "bad": "Disabled = spoofed packets may be accepted.",
        "fix": "sysctl -w net.ipv4.conf.all.rp_filter=1",
    },
    "world_writable_files": {
        "title": "World Writable Files",
        "category": "Filesystem",
        "risk": "High",
        "description": "Finds files writable by any user. Attackers could plant malicious code.",
        "good": "No world-writable files outside /proc and /sys.",
        "bad": "World-writable files allow unprivileged users to overwrite critical data.",
        "fix": "chmod o-w <file>  – remove world-write permission from affected files.",
    },
    "suid_binaries": {
        "title": "SUID Binaries",
        "category": "Filesystem",
        "risk": "Medium",
        "description": "Lists binaries with the SUID bit set. They run with elevated privileges.",
        "good": "Only known system binaries (sudo, passwd, …) carry the SUID bit.",
        "bad": "Unexpected SUID binaries are a common privilege escalation vector.",
        "fix": "chmod u-s <file>  – remove SUID bit from untrusted binaries.",
    },
    "/tmp_noexec": {
        "title": "/tmp noexec",
        "category": "Filesystem",
        "risk": "Medium",
        "description": "Checks if /tmp is mounted with noexec. Prevents execution of binaries placed there.",
        "good": "noexec is set – binaries in /tmp cannot be executed directly.",
        "bad": "Without noexec, attackers can drop and run malware in /tmp.",
        "fix": "Add 'noexec' to the /tmp entry in /etc/fstab, then remount.",
    },
    "/tmp_sticky_bit": {
        "title": "/tmp Sticky Bit",
        "category": "Filesystem",
        "risk": "Low",
        "description": "Checks if the sticky bit is set on /tmp. Prevents users from deleting each other's files.",
        "good": "Sticky bit is set – only the owner can delete their own files.",
        "bad": "Without sticky bit, any user can delete or rename files in /tmp.",
        "fix": "chmod +t /tmp",
    },
}


def _divider():
    print("  " + "─" * 40)


def print_help() -> None:
    print(LOGO_FULL)
    print("  Usage")
    _divider()
    print("    secfetch                      Full security overview")
    print("    secfetch fastscan             Scan with reduced checks (see config.py)")
    print("    secfetch --short              Compact one-box summary")
    print("    secfetch live                 Live monitoring, auto-refresh every 5s")
    print("    secfetch live --interval <n>  Refresh every n seconds")
    print("    secfetch improve              Show issues with fix suggestions")
    print("    secfetch improve --auto       Interactive auto-fix selection")
    print("    secfetch help                 This help page")
    print("    secfetch help <check>         Detailed info about a check")
    print()
    print("  Available Checks")
    _divider()
    for key, info in CHECK_DESCRIPTIONS.items():
        cat = info["category"]
        title = info["title"]
        print(f"    {key:<20}  {cat:<20}  {title}")
    print()


def print_check_help(name: str) -> None:
    key = name.lower().replace(" ", "_")
    info = CHECK_DESCRIPTIONS.get(key)

    if not info:
        log_warning(f"User requested help for unknown check: '{name}'")
        print(f"\n  [!] Unknown check: '{name}'")
        print("  Run 'secfetch help' to see all available checks.\n")
        return

    print()
    print(f"  {info['title']}")
    _divider()
    print(f"    Category    {info['category']}")
    print(f"    Risk        {info['risk']}")
    print()
    print(f"    {info['description']}")
    print()
    print("  ✔  Good state")
    print(f"    {info['good']}")
    print()
    print("  ✖  Bad state")
    print(f"    {info['bad']}")
    print()
    print("  Fix")
    _divider()
    print(f"    {info['fix']}")
    print()
