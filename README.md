```
                   ____     __       __  
   ________  _____/ __/__  / /______/ /_ 
  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/ 
```

**secfetch** is a lightweight **Linux security inspection CLI**.

It provides a quick overview of security‑relevant system configuration — similar to fetch tools like `neofetch` or `fastfetch`, but focused on **security posture instead of aesthetics**.

secfetch inspects kernel protections, system hardening settings, and network exposure to give a fast overview of the current system state.

---

# Overview

secfetch performs **read‑only security checks** and prints the results in a compact overview.

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

# Example

```
$ secfetch

System
------
Kernel               6.8.9
Secure Boot          Enabled

Kernel Security
---------------
ASLR                 Full
Lockdown             integrity
LSM                  apparmor, bpf

Kernel Hardening
----------------
kptr_restrict        Fully Restricted
dmesg_restrict       Enabled
ptrace_scope         Restricted
modules_disabled     Disabled
unprivileged_bpf     Disabled

Network
-------
Firewall             Active
Open Ports           22, 631
IPv6                 Enabled
```

---

# Installation

## One‑liner installation

```
git clone https://github.com/YOURNAME/secfetch.git && cd secfetch && pip install .
```

After installation:

```
secfetch
```

---

## Manual installation

Clone the repository:

```
git clone https://github.com/YOURNAME/secfetch.git
cd secfetch
```

Install the package:

```
pip install .
```

You can now run:

```
secfetch
```

---

# Usage

Run the default security overview:

```
secfetch
```

Show the program version:

```
secfetch --version
```

Display an explanation for a specific check:

```
secfetch help aslr
```

Example:

```
secfetch help ptrace_scope
```

---

# Security Checks

secfetch currently inspects:

### System

- Kernel version
- Secure Boot status

### Kernel Security

- ASLR
- Kernel Lockdown
- Linux Security Modules (LSM)

### Kernel Hardening

- kptr_restrict
- dmesg_restrict
- ptrace_scope
- modules_disabled
- unprivileged_bpf_disabled

### Network

- Firewall state
- Open ports
- IPv6 status

---

# Design Goals

- **Read‑only** inspection
- **No root required** where possible
- **Minimal dependencies**
- **Fast execution**
- **Deterministic checks**

secfetch is designed to provide a **quick security overview**, not a full security audit.

---

# Non‑Goals

secfetch intentionally does **not**:

- perform vulnerability scanning
- modify system configuration
- run intrusive network scans
- replace security auditing tools

For deeper auditing consider tools such as:

- `lynis`
- `checksec`
- distribution security benchmarks

---

# Roadmap

Planned improvements include:

- additional kernel hardening checks
- improved firewall detection
- optional deep scan mode
- extended network inspection
- improved CLI features

---

# Contributing

Contributions are welcome.

Please follow these guidelines:

- keep checks deterministic
- avoid unnecessary dependencies
- document detection logic clearly
- prefer reading from `/proc` and `/sys` where possible
- avoid intrusive scanning techniques

---

# License

This project is licensed under the **GNU General Public License v3.0 (GPL‑3.0)**.

See the [LICENSE](LICENSE) file for details.
