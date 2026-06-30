<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:1f6feb&height=180§ion=header&text=&fontSize=0" width="100%"/>

<br>

```
                   ____
   ________  _____/ __/__  __________
  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/
 (__  )  __/ /__/ __/  __(__  ) /__
/____/\___/\___/_/  \___/____/\___/
```

<br>

[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=20&duration=3000&pause=1000&color=58A6FF¢er=true&vCenter=true&repeat=true&width=550&height=50&lines=Linux+Security+Inspection+CLI;secfetch+%2B+secscan;Two+tools.+One+purpose.)](https://github.com/ake13-art/secfesc)

<br>

![Version](https://img.shields.io/badge/version-1.7.0-1f6feb?style=for-the-badge&labelColor=0d1117)
![License](https://img.shields.io/badge/license-GPL--3.0-58a6ff?style=for-the-badge&labelColor=0d1117)
![Python](https://img.shields.io/badge/python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=white&labelColor=0d1117)

<br>

> **This project uses AI as a development tool.**
> **All code is human‑reviewed, tested and maintained by the author.**

</div>

<br>

---

<br>

<div align="center">

## Quick Start

</div>

<br>

```bash
pip install secfesc
```

```bash
secfetch          # Quick security overview
secscan           # Basic audit (no root)
sudo secscan --full   # Complete audit (requires root)
```

<br>

---

<br>

<div align="center">

## Two Tools in One

</div>

<br>

| Tool | Purpose | Run as |
|------|---------|--------|
| **secfetch** | Quick security overview | User |
| **secscan** | Deep audit (Lynis-like) | User or root |

**secfetch** provides instant security status at a glance.

**secscan** delivers a Lynis-style audit — SSH, users and groups today, growing toward full coverage.

<br>

---

<br>

<div align="center">

## Commands

</div>

<br>

### secfetch

| Command | Description |
|---------|-------------|
| `secfetch` | Full security overview |
| `secfetch --short` | Compact one-box summary |
| `secfetch fastscan` | Fast scan (enabled checks only, see `~/.config/secfesc/checks.conf`) |
| `secfetch live` | Live monitoring, auto-refresh every 5 s |
| `secfetch live --interval N` | Live monitoring, refresh every N seconds |
| `secfetch improve` | Show failing checks with fix suggestions |
| `secfetch improve --auto` | Interactive auto-fix selection and apply |
| `secfetch help` | List all checks |
| `secfetch help <name>` | Detailed info about a check |

### secscan

| Command | Description |
|---------|-------------|
| `secscan` | Basic audit (no root) |
| `secscan --full` | Complete audit |
| `secscan --quick` | Essential checks only |
| `secscan --category ssh` | Specific category |
| `secscan --report json` | Export results to stdout |
| `secscan --report html --output audit.html` | Export report to file |
| `secscan --verbose` | Enable verbose/debug output |
| `secscan --quiet` | Suppress human summary |

<br>

---

<br>

<div align="center">

## Checks

</div>

<br>

### secfetch (Currently ~20 checks)

| Category | Checks |
|----------|--------|
| System | Kernel, Secure Boot |
| Kernel Security | ASLR, Lockdown, LSM |
| Kernel Hardening | kptr_restrict, dmesg_restrict, ptrace_scope |
| Network | Firewall, Ports, Services, SYN Cookies |
| Filesystem | SUID, World Writable, /tmp |

### secscan (active checks as of v1.8.0)

| Category | Checks |
|----------|--------|
| SSH | Root login, empty passwords, password auth, legacy protocol, X11 forwarding, MaxAuthTries |
| Users | UID 0 accounts, empty passwords (root), duplicate UID/name |
| Groups | Duplicate GID/name, root group members |
| Authentication | Password ageing policy, weak hash method, default umask (`/etc/login.defs`) |
| Firewall | Active firewall detection (firewalld/ufw/nftables/iptables) |
| Cron | World-writable cron paths/files, unrestricted cron policy |
| Permissions | Mode & ownership of `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` |
| Boot | GRUB boot-menu password protection, world-readable password hash |
| Kernel | ASLR, kptr/dmesg/ptrace restrictions, suid_dumpable, BPF, SysRq, kexec, perf (`/proc/sys`) |
| Services | Enabled legacy/cleartext systemd units (telnet, rsh, tftp, NIS, …) |
| Logging | Active system logger, auditd, persistent journald storage |

### secscan (roadmap)

| Version | Categories | Target |
|---------|------------|--------|
| v2.0 | Filesystem, extended Network | ~160 |
| v2.4 | Compliance (CIS/NIST) | ~300+ |

> secscan aims to become a Lynis-style auditor. The roadmap numbers are targets, not shipped counts.

<br>

---

<br>

<div align="center">

## Example Output

</div>

<br>

```
                   ____
   ________  _____/ __/__  __________
  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/
 (__  )  __/ /__/ __/  __(__  ) /__
/____/\___/\___/_/  \___/____/\___/

  System
  ────────────────────────────────────────
    ✔  Kernel                6.14.6-zen1-1-zen
    ✔  Secure Boot           Enabled

  Kernel Security
  ────────────────────────────────────────
    ✔  ASLR                  Full
    ✔  Lockdown              integrity
    ✔  LSM                   landlock,lockdown,yama,integrity,apparmor,bpf

  Network
  ────────────────────────────────────────
    ✔  Firewall Rules        firewalld active
    ✔  Open Ports            22 (SSH/TCP), 53 (DNS/UDP)

  Security Score
  ────────────────────────────────────────
    System               [████████████]  92/100
    Kernel Security      [████████████]  95/100
    Network              [██████████░░]  80/100
    ────────────────────────────────────────
    Total                [████████████]  88/100
```

<br>

---

<br>

<div align="center">

## Documentation

</div>

<br>

| Document | Description |
|----------|-------------|
| [Installation](docs/INSTALL.md) | How to install |
| [Configuration](docs/CONFIG.md) | Configure checks |
| [Usage](docs/USAGE.md) | CLI reference |
| [Architecture](docs/ARCHITECTURE.md) | Project structure |
| [ROADMAP.md](ROADMAP.md) | Development plans |

<br>

---

<br>

<div align="center">

## License

</div>

<br>

GNU General Public License v3.0 - See [LICENSE](LICENSE)

<br><br>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:1f6feb&height=120§ion=footer" width="100%"/>
