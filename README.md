```
                   ____     __       __
   ________  _____/ __/__  / /______/ /_
  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/
```

**secfetch** is a lightweight **Linux security inspection CLI**.

It provides a quick overview of security‑relevant system configuration — similar to fetch tools like `neofetch` or `fastfetch`, but focused on **security posture instead of aesthetics**.

secfetch inspects kernel protections, system hardening settings, and network exposure to give a fast, readable overview of the current system state.

---

# Overview

secfetch performs **read‑only security checks** and prints the results in a compact, categorized overview.

It focuses on:

- Kernel security features
- Kernel hardening parameters
- Linux Security Modules
- Secure Boot status
- Firewall state
- Open network ports
- IPv6 configuration

The tool is intentionally **lightweight, dependency‑free, and non‑intrusive**.

secfetch **does not modify system configuration** and **does not perform vulnerability scans**.

---

# Example Output

### Full mode

```
$ secfetch

  System
  ────────────────────────────────────────
    Kernel                  •  6.8.9
    Secure Boot             ✔  Enabled

  Kernel Security
  ────────────────────────────────────────
    ASLR                    ✔  Full
    Lockdown                ✔  integrity
    LSM                     ✔  apparmor, bpf

  Kernel Hardening
  ────────────────────────────────────────
    kptr_restrict           ✔  Fully Restricted
    dmesg_restrict          ✔  Enabled
    ptrace_scope            ✔  Restricted
    modules_disabled        ⚠  Disabled
    unprivileged_bpf        ✔  Disabled

  Network
  ────────────────────────────────────────
    Firewall                ✔  Active
    Open Ports              ⚠  22, 631
    IPv6                    •  Enabled

  Security Score
  ────────────────────────────────────────
    System                ████████████  85/100
    Kernel Security       ████████████  90/100
    Kernel Hardening      ████████░░░░  70/100
    Network               ██████████░░  78/100
  ────────────────────────────────────────
    Total                 ██████████░░  80/100
```

### Short mode

```
$ secfetch --short

  ┌────────────────Security Status─────────────────┐
  │  System    Kernel: 6.8.9           Secure Boot: ✔ Enabled  │
  │  Security  ASLR: ✔ Full            Lockdown: ✔ integrity   │
  │  Network   Firewall: ✔ Active      Ports: ⚠ 22, 631        │
  │  Score     ███████████████  80/100                         │
  └─────────────────────────────────────────────────┘
```

The short mode is designed for use in `.bashrc` / `.zshrc` as a terminal startup overview.

---

# Installation

## One‑liner

```bash
git clone https://github.com/ake13-art/secfetch.git && cd secfetch && pip install .
```

## Manual

```bash
git clone https://github.com/ake13-art/secfetch.git
cd secfetch
pip install .
```

After installation:

```bash
secfetch
```

---

# Usage

| Command | Description |
|---|---|
| `secfetch` | Full security overview |
| `secfetch --short` | Compact one‑box overview |
| `secfetch --version` | Show version |
| `secfetch help <check>` | Explain a specific check |

Examples:

```bash
secfetch help aslr
secfetch help ptrace_scope
```

---

# Security Checks

### System

| Check | Description |
|---|---|
| Kernel | Running kernel version |
| Secure Boot | UEFI Secure Boot state |

### Kernel Security

| Check | Description |
|---|---|
| ASLR | Address Space Layout Randomization |
| Lockdown | Kernel lockdown mode |
| LSM | Active Linux Security Modules |

### Kernel Hardening

| Check | Description |
|---|---|
| kptr_restrict | Kernel pointer exposure |
| dmesg_restrict | dmesg access restriction |
| ptrace_scope | ptrace attach scope |
| modules_disabled | Kernel module loading state |
| unprivileged_bpf | Unprivileged BPF access |

### Network

| Check | Description |
|---|---|
| Firewall | Active firewall detection |
| Open Ports | Listening TCP ports |
| IPv6 | IPv6 enabled state |

---

# Security Score

secfetch calculates a **weighted security score** from 0 to 100, broken down by category:

- **System**
- **Kernel Security**
- **Kernel Hardening**
- **Network**

The score is displayed as a progress bar at the end of the full output.  
It is intended as a rough orientation — not a compliance metric.

---

# Project Structure

```
secfetch/
├── src/
│   └── secfetch/
│       ├── checks/
│       │   ├── kernel/
│       │   │   ├── aslr.py
│       │   │   ├── hardening.py
│       │   │   ├── lockdown.py
│       │   │   └── lsm.py
│       │   ├── network/
│       │   │   ├── firewall.py
│       │   │   ├── ipv6.py
│       │   │   └── ports.py
│       │   └── system/
│       │       ├── kernel.py
│       │       └── secureboot.py
│       ├── core/
│       │   ├── check.py
│       │   ├── loader.py
│       │   └── scoring.py
│       ├── ui/
│       │   └── output.py
│       └── main.py
├── pyproject.toml
└── README.md
```

Each check is a self‑contained module. The loader discovers and runs them automatically.

---

# Design Goals

- **Read‑only** — no system modifications
- **No root required** where possible
- **Minimal dependencies** — stdlib only
- **Fast execution** — no heavy scanning
- **Modular** — checks are easy to add or remove
- **Deterministic** — consistent results across runs

secfetch is designed for a **quick security overview**, not a full audit.

---

# Non‑Goals

secfetch intentionally does **not**:

- perform vulnerability scanning
- modify system configuration
- run intrusive network scans
- replace dedicated security auditing tools

For deeper auditing consider:

- [`lynis`](https://cisofy.com/lynis/)
- [`checksec`](https://github.com/slimm609/checksec.sh)
- distribution security benchmarks

---

# Roadmap

### v1.2 – Config & Performance
- Config file at `~/.config/secfetch/checks.conf`
- Enable / disable individual checks via config
- `secfetch fastscan` — runs only enabled checks
- Code refactoring for better maintainability

### Beyond
- Additional filesystem checks
- Improved firewall backend detection
- Extended network inspection

---

# Contributing

Contributions are welcome.

Please follow these guidelines:

- keep checks **deterministic**
- avoid **unnecessary dependencies**
- document **detection logic** clearly
- prefer reading from `/proc` and `/sys`
- avoid intrusive scanning techniques

---

# License

This project is licensed under the **GNU General Public License v3.0 (GPL‑3.0)**.

See the [LICENSE](LICENSE) file for details.
