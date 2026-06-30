# Roadmap

Development roadmap for secfesc (secfetch + secscan).

---

## Vision

**secfetch** - Quick security overview for rapid assessment.

**secscan** - Comprehensive Linux security audit tool (Lynis alternative).

secscan is the primary focus. secfetch remains as-is for quick checks.

---

## Architecture Unification

### Current Issue

Two separate check systems exist:

1. **secfetch**: `@security_check` decorator-based
2. **secscan**: Custom engine with categories

### Goal: Single System

Future: Both tools share one check framework.
secscan becomes the foundation, secfetch wraps it.

---

## secscan Phases

### Phase 1: Core Infrastructure ✅ (v1.6.0)

**Goal**: secscan can run real audits.

| Category | Checks Needed | Status |
|----------|---------------|--------|
| SSH | Root login, PermitEmptyPasswords, PasswordAuthentication, Protocol, X11Forwarding, MaxAuthTries | ✅ done |
| Users | Empty passwords, UID 0 accounts, duplicate UID/name | ✅ done |
| Groups | Duplicate GID/name, root group members | ✅ done |

**Milestone**: `secscan --category ssh` returns real findings. ✅

Built on a shared audit-check framework (`secscan/core/registry.py` +
`@audit_check`). Adding a check is now: drop a function in
`secscan/core/categories/<cat>.py`, decorate it, return `AuditFinding`s.

### Phase 1b: Hardening & Policy ✅ (v1.7.0)

| Category | Checks Needed | Status |
|----------|---------------|--------|
| Authentication | Password ageing, weak hash, UMASK (`/etc/login.defs`) | ✅ done |
| Firewall | Active firewall detection (firewalld / ufw / nftables / iptables) | ✅ done |
| Cron | World-writable cron paths/files, unrestricted cron policy | ✅ done |
| Permissions | Mode & ownership of `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group` | ✅ done |

### Phase 2: Foundation ✅ (v1.8.0)

**Goal**: 100+ working checks.

| Category | Checks Needed | Status |
|----------|---------------|--------|
| Boot | GRUB boot-menu password protection, world-readable password hash | ✅ done |
| Kernel | Runtime sysctl hardening: ASLR, kptr/dmesg/ptrace, suid_dumpable, BPF, SysRq, kexec, perf | ✅ done |
| Services | Enabled legacy/cleartext systemd units (telnet, rsh, tftp, NIS, …) | ✅ done |
| Logging | Active system logger, auditd, persistent journald storage | ✅ done |

**Milestone**: all four categories run without root (read only `/proc/sys` and
`systemctl` queries) and are included in `secscan`, `--quick` and `--full`. ✅

### Phase 3: Filesystem & Network

**Goal**: Complete filesystem and network auditing.

| Category | Checks Needed |
|----------|---------------|
| Filesystem | SUID/SGID, world-writable, sticky bit |
| Permissions | /etc/shadow, SSH keys, critical files |
| Network | DNS, NTP, interfaces, routes, firewall |

### Phase 4: Extended

**Goal**: 200+ checks.

| Category | Checks Needed |
|----------|---------------|
| Containers | Docker, Podman, privileges |
| Malware | rkhunter, chkrootkit integration |
| Certificates | SSL/TLS, SSH keys, GPG |
| PHP | Config, disabled functions |

### Phase 5: Compliance

**Goal**: Ready for CIS/NIST audits.

| Category | Checks Needed |
|----------|---------------|
| CIS | CIS Benchmarks (basic) |
| NIST | NIST SP 800-53 (basic) |
| Reporting | JSON/HTML/CSV, trends |

### Phase 6: Full Parity

**Goal**: ~300 checks, Lynis feature parity.

| Category | Status |
|----------|--------|
| All above | Complete |
| Databases | MySQL, PostgreSQL, Redis |
| Mail | Postfix, Sendmail |
| Webservers | Apache, Nginx |
| Virtualization | KVM, Xen, VMware |

---

## secfetch Roadmap

secfetch stays focused on security. No CPU/GPU/Memory features.

### v1.6.x

- [ ] Maintain current checks
- [ ] Update any broken checks for new kernels
- [ ] Better error messages

### v2.0 (phased with secscan v2.0)

- [ ] Integration with secscan framework
- [ ] Shared check infrastructure
- [ ] Remove duplication

---

## Check Implementation Guide

### Adding a secscan Check

1. Add (or open) a module in `secscan/core/categories/<category>.py`
2. Write a function decorated with `@audit_check("<category>")` that returns
   an `AuditFinding`, a list of them, or `None`
3. That's it — discovery and the runner pick it up automatically

```python
from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check

@audit_check("ssh")
def check_ssh_root_login() -> AuditFinding | None:
    # ... check logic ...
    return AuditFinding(
        category="ssh",
        check_id="SSH-7412",
        title="Root login over SSH is permitted",
        severity="high",          # high -> error, medium -> warning, low -> note
        status="found",
        description="Root login is permitted",
        solution="Set PermitRootLogin no in /etc/ssh/sshd_config",
        affected="PermitRootLogin yes",
    )
```

### Adding to secfetch (legacy)

Use existing `@security_check` decorator (until v2.0 unification).

---

## Version History

| Version | Focus |
|---------|-------|
| v1.8.0 | secscan Phase 2: boot, kernel, services, logging |
| v1.7.0 | secscan categories: authentication, firewall, cron, permissions |
| v1.6.1 | Quality & consistency: dead-code removal, naming consistency, banner, +tests (75%→80%) |
| v1.6.0 | secscan real findings (SSH/Users/Groups), unified shared check framework, packaging fix |
| v1.5.3 | secscan Export (JSON/HTML/CSV), Bug fixes |
| v1.5.2 | Bug fixes |
| v1.5.1 | Auto-fix improvements |
| v1.5.0 | secfetch improve command |
| v1.4.0 | Live monitoring |
| v1.3.0 | Port database, services check |
| v1.2.0 | Firewall detection |
| v1.1.0 | Modular check system |
| v1.0.0 | Initial release |

---

## Contributing

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how to add checks.
Open an issue to discuss new categories or features.