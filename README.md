
<div align="center">
  
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:1f6feb&height=180§ion=header&text=&fontSize=0" width="100%"/>

<br>

```
                   ____     __       __
   ________  _____/ __/__  / /______/ /_
  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/

```

<br>

[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=20&duration=3000&pause=1000&color=58A6FF¢er=true&vCenter=true&repeat=true&width=550&height=50&lines=Linux+Security+Inspection+CLI;Like+neofetch,+but+for+your+security;One+command.+Full+overview.+Zero+bloat.)](https://github.com/ake13-art/secfetch)

<br>

![Version](https://img.shields.io/badge/version-1.5-1f6feb?style=for-the-badge&labelColor=0d1117)
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

  ## ⚡ Quick Start

</div>

<br>

```bash
pip install secfetch
```

```bash
secfetch
```

<br>

---

<br>

<div align="center">

  ## 🖥️ Commands

</div>

<br>

| Command | What it does |
|:---|:---|
| `secfetch` | Full security overview |
| `secfetch fastscan` | Only enabled checks — faster |
| `secfetch --short` | Compact one‑box summary |
| `secfetch live` | Live monitoring — auto refresh every 5s |
| `secfetch live --interval <n>` | Custom refresh interval |
| `secfetch improve` | Show issues with fix suggestions |
| `secfetch improve --auto` | Interactive auto-fix selection |
| `secfetch help <check>` | Detailed info, risk level & fix |
| `secfetch -h` | Show all available options |

<br>

---

<br>

<div align="center">

  ## 🔧 Improve Command

</div>

<br>

The `improve` command helps you fix security issues:

```bash
secfetch improve
```

Shows all failed checks with risk levels and fix suggestions:

```
  3 issue(s) found
  ✖  kptr_restrict           Risk: Medium  [auto-fixable]
     Fix: echo 2 | sudo tee /proc/sys/kernel/kptr_restrict
  ⚠  modules_disabled        Risk: High  [auto-fixable]
     Fix: echo 1 | sudo tee /proc/sys/kernel/modules_disabled  (irreversible!)
  ⚠  Lockdown                Risk: Medium
     Fix: Add boot parameters: lsm=lockdown lockdown=integrity
```

### Auto-Fix

```bash
secfetch improve --auto
```

Interactive selection with toggle UI and safety warnings:

```
  Auto-Fix  —  secfetch improve --auto
  ───────────────────────────────────────────────────────
    [1] [✔] kptr_restrict       sudo sysctl -w kernel.kptr_restrict=2
    [2] [✖] modules_disabled    sudo sysctl -w kernel.modules_disabled=1
         ⚠  Irreversible until reboot!
  Require manual fix  —  run secfetch improve for details:
    ⚠  Lockdown               none
  ───────────────────────────────────────────────────────
  1 fix(es) selected.
  Toggle: 1-2 | a = all | n = none | Enter = confirm | q = quit
```

**Features:**
- Persistent fixes (written to `/etc/sysctl.d/99-secfetch.conf`)
- Risky fix warnings (e.g. `modules_disabled`)
- Service auto-disable for suspicious services (telnetd, rshd, etc.)
- Firewall availability check (won't offer ufw if not installed)

<br>

---

<br>

<div align="center">

  ## 🔍 Security Checks

</div>

<br>

| Category | Checks |
|:---|:---|
| **System** | Kernel, Secure Boot |
| **Kernel Security** | ASLR, Lockdown, LSM |
| **Kernel Hardening** | kptr_restrict, dmesg_restrict, ptrace_scope, modules_disabled, unprivileged_bpf |
| **Network** | Firewall, Firewall Rules, IPv6, Open Ports, Services, TCP SYN Cookies, Reverse Path Filter |
| **Filesystem** | World Writable Files, SUID Binaries, /tmp noexec, /tmp Sticky Bit |
Use `secfetch help <check>` for detailed information.

<br>

---

<br>

<div align="center">

  ## 📸 Example Output

</div>

<br>

```
                   ____     __       __
   ________  _____/ __/__  / /______/ /_
  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/
  System
  ────────────────────────────────────────
    •  Kernel                  6.x.x-arch1-1
    ✖  Secure Boot             Disabled
  Kernel Security
  ────────────────────────────────────────
    ✔  ASLR                    Full
    ⚠  Lockdown                none
    ✔  LSM                     capability,landlock
  Kernel Hardening
  ────────────────────────────────────────
    ✔  kptr_restrict           Fully Restricted
    ✔  dmesg_restrict          Enabled
    ✔  ptrace_scope            Restricted
    ✔  modules_disabled        Disabled
    ✔  unprivileged_bpf        Permanently Disabled
  Network
  ────────────────────────────────────────
    ✔  Firewall                ufw active: 10 rules
    •  IPv6                    Enabled
    ⚠  Open Ports              22 (SSH/TCP), 53 (domain/UDP)
    ✔  Reverse Path Filter     Strict
    ✔  Services                24 running, none flagged
    ✔  TCP SYN Cookies         Enabled
  Security Score
  ────────────────────────────────────────
    System                [██████████░░]  50/100
    Kernel Security       [██████████░░]  66/100
    Kernel Hardening      [████████████] 100/100
    Network               [██████████░░]  85/100
  ────────────────────────────────────────
    Total                 [██████████░░]  78/100
```

<br>

---

<br>

<div align="center">

  ## ⚙️ Configuration

</div>

<br>

Checks can be enabled/disabled in `~/.config/secfetch/checks.conf` (created on first run).

```ini

[checks]
# Fast checks (run by default)
aslr = true
secure_boot = true
kernel_version = true
...
# Full scan only (slower)
lsm = false
world_writable = false
...
```

<br>

---

<br>

<div align="center">

  ## 🗺️ Roadmap

</div>

<br>

| Version | Features |
|:--------|:---------|
| **v1.6** | SSH config checks, User/Group audit, Export (JSON/HTML/CSV/XML) |
| **v2.0** | Deep scan, CVE lookups, and much more

<br>

---

<br>

<div align="center">

  ## 📜 License
This project is licensed under the **GNU General Public License v3.0 (GPL‑3.0)**.
See the [LICENSE](LICENSE) file for details.

<br>

---

<br>

<img src="https://img.shields.io/github/stars/ake13-art/secfetch?style=for-the-badge&logo=github&color=f0c000&logoColor=white&labelColor=0d1117" />
<img src="https://img.shields.io/github/forks/ake13-art/secfetch?style=for-the-badge&logo=git&color=58a6ff&logoColor=white&labelColor=0d1117" />
<img src="https://img.shields.io/github/issues/ake13-art/secfetch?style=for-the-badge&logo=github&color=8b949e&logoColor=white&labelColor=0d1117" />

<br><br>

*⭐ Star this repo if secfetch is useful to you*

<br>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:1f6feb&height=120§ion=footer" width="100%"/>
