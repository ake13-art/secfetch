CHECK_HELP = {
    "aslr": "ASLR (Address Space Layout Randomization) randomizes memory addresses to prevent exploits.",
    "secureboot": "Secure Boot ensures only signed bootloaders and kernels can start during boot.",
    "lockdown": "Kernel Lockdown restricts kernel features that could allow privilege escalation.",
    "lsm": "Linux Security Modules provide mandatory access control (AppArmor, SELinux, etc).",
    "kptr_restrict": "Controls whether kernel pointer addresses are visible to users.",
    "dmesg_restrict": "Restricts access to the kernel log buffer (dmesg) for unprivileged users.",
    "ptrace_scope": "Limits the ability of processes to trace other processes.",
    "modules_disabled": "Prevents loading new kernel modules after boot.",
    "unprivileged_bpf": "Controls whether unprivileged users can use BPF.",
    "firewall": "Shows whether a firewall (iptables/nftables/ufw) is active.",
    "ipv6": "Indicates whether IPv6 networking is enabled.",
}
