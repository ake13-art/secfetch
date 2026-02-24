# secfetch

secfetch is a security-oriented system inspection CLI for Linux.

Lightweight security state inspector for Linux — bridging the gap between pretty fetch tools and heavy-duty audit frameworks.

Unlike traditional "fetch" tools that focus on aesthetic system information,
secfetch inspects security-relevant configuration and exposes potential
hardening gaps in a clear and non-invasive way.

---

## Purpose

secfetch provides a quick, read-only overview of a system’s security posture.

It focuses on:

- Kernel hardening state
- Attack surface indicators
- Privilege configuration
- Namespaces and sandboxing status
- Linux Security Modules (AppArmor / SELinux)
- Secure Boot status
- Firewall state
- Selected security-relevant sysctl parameters
- VPN connection status (active / last known connection)

secfetch does **not** modify system configuration.
It does **not** auto-harden the system.
It does **not** perform intrusive scans.

---

## Philosophy

- Read-only by default
- No automatic remediation
- Minimal dependencies
- Transparent checks
- Deterministic output
- Clear reporting without alarmism
- JSON output for automation

secfetch is an inspection tool, not a security product.

---

## Disclaimer!
At this moment, this is just an attempt of a fetch setup. However, the plan is to make this a constantly evolving tool.

---

## Roadmap
#### v0.1

- Kernel version
- ASLR status
- LSM detection
- Secure Boot check
- Firewall detection

## Non-Goals

- No automatic system hardening
- No vulnerability scanning
- No network probing
- No root-required design (where avoidable)

---

## Contributing
Contributions are welcome.

Please:
- Keep checks deterministic
- Avoid alarmist language
- Document detection logic clearly
- Prefer explicit paths over shell calls
- Avoid unnecessary dependencies

---

# License
This project is licensed under the GNU General Public License v3.0 (GPL-3.0).
See the LICENSE file for details.
