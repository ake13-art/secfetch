```
                   ____     __       __
   ________  _____/ __/__  / /______/ /_
  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/
```
# version 1.3.1

A lightweight **Linux security inspection CLI** — like neofetch, but for your security posture.

> **Note:** This project uses AI as a development tool. All code is human‑reviewed, tested and maintained by the author.

---

## Installation

```bash
git clone https://github.com/ake13-art/secfetch.git && cd secfetch && pip install .
```

---

## Usage

| Command                 | Description                         |
| ----------------------- | ----------------------------------- |
| `secfetch`              | Full security overview              |
| `secfetch fastscan`     | Only enabled checks (faster)        |
| `secfetch --short`      | Compact one‑box summary             |
| `secfetch help <check>` | Detailed info, risk level and fix   |
| `secfetch -h`           | Help page with all available checks |

---

## Checks

| Key                    | Category         | Risk   |
| ---------------------- | ---------------- | ------ |
| `kernel`               | System           | Info   |
| `secure boot`          | System           | Medium |
| `aslr`                 | Kernel Security  | High   |
| `lockdown`             | Kernel Security  | Medium |
| `lsm`                  | Kernel Security  | Medium |
| `kptr_restrict`        | Kernel Hardening | Medium |
| `dmesg_restrict`       | Kernel Hardening | Medium |
| `ptrace_scope`         | Kernel Hardening | Medium |
| `modules_disabled`     | Kernel Hardening | Low    |
| `unprivileged_bpf`     | Kernel Hardening | Medium |
| `firewall`             | Network          | Medium |
| `firewall rules`       | Network          | Low    |
| `ipv6`                 | Network          | Low    |
| `open ports`           | Network          | Medium |
| `services`             | Network          | Medium |
| `tcp syn cookies`      | Network          | Medium |
| `reverse path filter`  | Network          | Medium |
| `world writable files` | Filesystem       | High   |
| `suid binaries`        | Filesystem       | Medium |
| `/tmp noexec`          | Filesystem       | Medium |
| `/tmp sticky bit`      | Filesystem       | Low    |

Use `secfetch help <check>` for details on any check.

---

## Example Output

**Full mode** — `secfetch`
```
                   ____     __       __
   ________  _____/ __/__  / /______/ /_
  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/

  System
  ────────────────────────────────────────
    •  Kernel                  6.19.6-arch1-1
    ✖  Secure Boot             Disabled

  Kernel Security
  ────────────────────────────────────────
    ✔  ASLR                    Full
    ⚠  Lockdown                none
    ✔  LSM                     capability,landlock

  Kernel Hardening
  ────────────────────────────────────────
    ✖  kptr_restrict           Unrestricted
    ✔  dmesg_restrict          Enabled
    ✔  ptrace_scope            Restricted
    ⚠  modules_disabled        Disabled
    ✔  unprivileged_bpf        Permanently Disabled

  Network
  ────────────────────────────────────────
    ⚠  Firewall Rules          No rules found
    •  IPv6                    Enabled
    ⚠  Open Ports              53 (domain/UDP), 68 (bootpc/UDP)
    ✔  Reverse Path Filter     Strict
    ⚠  Services                28 running, 26 unexpected
    ✔  TCP SYN Cookies         Enabled

  Security Score
  ────────────────────────────────────────
    System                [░░░░░░░░░░░░]  0/100
    Kernel Security       [██████████░░]  85/100
    Kernel Hardening      [████████░░░░]  72/100
    Network               [███████░░░░░]  65/100
  ────────────────────────────────────────
    Total                 [████████░░░░]  67/100
```

**Short mode** — `secfetch --short`
```
  ┌──────────────────────────────────────────────────────────┐
  │  System    Kernel: 6.19.6-arch1-1   Secure Boot: ✖      │
  │  Security  ASLR: ✔ Full             Lockdown: ⚠ none    │
  │  Network   Firewall: N/A            Ports: ⚠ 53, 68     │
  │  Score     [████████░░░░]  67/100                        │
  └──────────────────────────────────────────────────────────┘
```

Designed for `.bashrc` / `.zshrc` as a terminal startup overview.
Fastscan checks can be toggled in `config.conf` (created on first run).

---

## Short Mode Layout

In `output.py` you can switch the `--short` style:

```python
SHORT_LAYOUT = "box"    # bordered box (default)
# SHORT_LAYOUT = "side" # logo left, info right
```

---

## Roadmap

**v1.4** — Live monitoring (`secfetch live`): firewall/port watch with configurable refresh rate

**v2.0** — `secfetch deepscan` with CVE lookups and system fingerprinting · AUR package

---

# License

This project is licensed under the **GNU General Public License v3.0 (GPL‑3.0)**.

See the [LICENSE](LICENSE) file for details.
