"""Kernel hardening checks (category: kernel).

Reads runtime ``sysctl`` values from ``/proc/sys`` (world-readable), so the
checks run as a normal user. A parameter whose file is missing (the feature is
not compiled in) is skipped silently rather than flagged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_read_file

_CAT = "kernel"


@dataclass(frozen=True)
class _Sysctl:
    path: str          # /proc/sys file to read
    key: str           # dotted sysctl name (for display / solution)
    check_id: str
    title: str
    severity: str
    is_insecure: Callable[[int], bool]
    description: str
    secure: str        # the value to set for a hardened system


# Each rule maps a sysctl to "what counts as insecure" plus how to fix it.
SYSCTLS = [
    _Sysctl(
        "/proc/sys/kernel/randomize_va_space", "kernel.randomize_va_space",
        "KRNL-5677", "ASLR is not fully enabled", "medium",
        lambda v: v < 2,
        "Address-space layout randomisation is weakened; only full ASLR (2) "
        "randomises the heap as well as stack and libraries.",
        "2",
    ),
    _Sysctl(
        "/proc/sys/kernel/kptr_restrict", "kernel.kptr_restrict",
        "KRNL-5820", "Kernel pointers are not restricted", "medium",
        lambda v: v < 1,
        "kptr_restrict is 0; kernel pointers leak through /proc and dmesg, "
        "easing exploitation of memory-corruption bugs.",
        "1",
    ),
    _Sysctl(
        "/proc/sys/kernel/dmesg_restrict", "kernel.dmesg_restrict",
        "KRNL-5821", "Unprivileged access to dmesg is allowed", "medium",
        lambda v: v == 0,
        "dmesg_restrict is 0; any user can read the kernel ring buffer, which "
        "can expose addresses and other sensitive details.",
        "1",
    ),
    _Sysctl(
        "/proc/sys/kernel/yama/ptrace_scope", "kernel.yama.ptrace_scope",
        "KRNL-5822", "ptrace scope is unrestricted", "medium",
        lambda v: v == 0,
        "ptrace_scope is 0; any process can attach to another of the same "
        "user, allowing credential and memory theft.",
        "1",
    ),
    _Sysctl(
        "/proc/sys/fs/suid_dumpable", "fs.suid_dumpable",
        "KRNL-6000", "SUID programs may create core dumps", "medium",
        lambda v: v != 0,
        "suid_dumpable is non-zero; core dumps of set-UID programs can leak "
        "privileged memory to disk.",
        "0",
    ),
    _Sysctl(
        "/proc/sys/kernel/unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled",
        "KRNL-5831", "Unprivileged BPF is enabled", "medium",
        lambda v: v == 0,
        "unprivileged_bpf_disabled is 0; unprivileged users can load BPF "
        "programs, a recurring source of kernel vulnerabilities.",
        "1",
    ),
    _Sysctl(
        "/proc/sys/kernel/sysrq", "kernel.sysrq",
        "KRNL-5830", "Magic SysRq key is enabled", "low",
        lambda v: v != 0,
        "kernel.sysrq is non-zero; the SysRq key exposes powerful debugging "
        "commands (including memory dumps and reboot) from the console.",
        "0",
    ),
    _Sysctl(
        "/proc/sys/kernel/kexec_load_disabled", "kernel.kexec_load_disabled",
        "KRNL-5695", "kexec loading is permitted", "low",
        lambda v: v == 0,
        "kexec_load_disabled is 0; an attacker with root could boot an "
        "unsigned kernel via kexec, bypassing Secure Boot.",
        "1",
    ),
    _Sysctl(
        "/proc/sys/kernel/perf_event_paranoid", "kernel.perf_event_paranoid",
        "KRNL-5680", "perf_event access is not restricted", "low",
        lambda v: v < 2,
        "perf_event_paranoid is below 2; the perf subsystem has a large "
        "attack surface and should be limited to privileged users.",
        "2",
    ),
]


def _read_int(path: str) -> int | None:
    """Return the first integer in *path*, or None if absent/unparsable."""
    raw = safe_read_file(path, default=None)
    if raw is None:
        return None
    token = raw.split()[0] if raw.split() else ""
    try:
        return int(token)
    except ValueError:
        return None


@audit_check("kernel")
def check_kernel() -> list[AuditFinding]:
    findings: list[AuditFinding] = []

    for rule in SYSCTLS:
        value = _read_int(rule.path)
        if value is None:
            continue
        if rule.is_insecure(value):
            findings.append(AuditFinding.found(
                _CAT, rule.check_id, rule.title, rule.severity,
                rule.description,
                f"Set '{rule.key} = {rule.secure}' "
                f"(e.g. in /etc/sysctl.d/99-secfesc.conf, then 'sysctl --system').",
                f"{rule.key} = {value}",
            ))

    return findings
