"""Fix data for security checks: sysctl mappings, auto-fix commands, and risk warnings."""
from __future__ import annotations

SYSCTL_FILE = "/etc/sysctl.d/99-secfetch.conf"

SYSCTL_PERSISTENT: dict[str, tuple[str, str]] = {
    "aslr": ("kernel.randomize_va_space", "2"),
    "kptr_restrict": ("kernel.kptr_restrict", "2"),
    "dmesg_restrict": ("kernel.dmesg_restrict", "1"),
    "ptrace_scope": ("kernel.yama.ptrace_scope", "1"),
    "modules_disabled": ("kernel.modules_disabled", "1"),
    "unprivileged_bpf": ("kernel.unprivileged_bpf_disabled", "2"),
    "ipv6": ("net.ipv6.conf.all.disable_ipv6", "1"),
    "tcp_syn_cookies": ("net.ipv4.tcp_syncookies", "1"),
    "reverse_path_filter": ("net.ipv4.conf.all.rp_filter", "1"),
}

AUTO_FIXES: dict[str, list[list[str]]] = {
    "aslr": [["sudo", "sysctl", "-w", "kernel.randomize_va_space=2"]],
    "kptr_restrict": [["sudo", "sysctl", "-w", "kernel.kptr_restrict=2"]],
    "dmesg_restrict": [["sudo", "sysctl", "-w", "kernel.dmesg_restrict=1"]],
    "ptrace_scope": [["sudo", "sysctl", "-w", "kernel.yama.ptrace_scope=1"]],
    "modules_disabled": [["sudo", "sysctl", "-w", "kernel.modules_disabled=1"]],
    "unprivileged_bpf": [["sudo", "sysctl", "-w", "kernel.unprivileged_bpf_disabled=2"]],
    "ipv6": [["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"]],
    "tcp_syn_cookies": [["sudo", "sysctl", "-w", "net.ipv4.tcp_syncookies=1"]],
    "reverse_path_filter": [["sudo", "sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"]],
    "/tmp_sticky_bit": [["sudo", "chmod", "+t", "/tmp"]],
    "firewall_rules": [["sudo", "ufw", "enable"]],
}

RISKY_FIXES: dict[str, str] = {
    "modules_disabled": "Irreversible until reboot! No new kernel modules can be loaded.",
}
