# secfetch version 1.2

```
                   ____     __       __
   ________  _____/ __/__  / /______/ /_
  / ___/ _ \ / ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/
```

**secfetch** is a lightweight **Linux security inspection CLI**.

---

## Usage

| Command                 | Description                         |
| ----------------------- | ----------------------------------- |
| `secfetch`              | Full security overview              |
| `secfetch scan`         | Same as above (explicit)            |
| `secfetch fastscan`     | Only enabled checks (faster)        |
| `secfetch --short`      | Compact one-box summary             |
| `secfetch help`         | Help page with all available checks |
| `secfetch help <check>` | Detailed info, risk level and fix   |
| `secfetch -h`           | Same as `secfetch help`             |

---

## Checks

| Key                    | Category         | Risk   | Description                        |
| ---------------------- | ---------------- | ------ | ---------------------------------- |
| `kernel`               | System           | Info   | Running kernel version             |
| `secure boot`          | System           | Medium | UEFI Secure Boot status            |
| `aslr`                 | Kernel Security  | High   | Address Space Layout Randomization |
| `lockdown`             | Kernel Security  | Medium | Kernel lockdown mode               |
| `lsm`                  | Kernel Security  | Medium | Active Linux Security Modules      |
| `kptr_restrict`        | Kernel Hardening | Medium | Kernel pointer visibility          |
| `dmesg_restrict`       | Kernel Hardening | Medium | dmesg access restriction           |
| `ptrace_scope`         | Kernel Hardening | Medium | ptrace process tracing scope       |
| `modules_disabled`     | Kernel Hardening | Low    | Kernel module loading after boot   |
| `unprivileged_bpf`     | Kernel Hardening | Medium | Unprivileged BPF program loading   |
| `firewall`             | Network          | Medium | UFW firewall status                |
| `ipv6`                 | Network          | Low    | IPv6 enabled/disabled              |
| `open ports`           | Network          | Medium | Locally listening ports            |
| `tcp syn cookies`      | Network          | Medium | SYN flood protection               |
| `reverse path filter`  | Network          | Medium | IP spoofing protection             |
| `world writable files` | Filesystem       | High   | Files writable by any user         |
| `suid binaries`        | Filesystem       | Medium | Binaries with SUID bit set         |
| `/tmp noexec`          | Filesystem       | Medium | /tmp mounted with noexec           |
| `/tmp sticky bit`      | Filesystem       | Low    | Sticky bit on /tmp                 |

---

## Short Mode Layout

In `output.py` you can switch the `--short` layout:

```python
SHORT_LAYOUT = "box"   # categories in a bordered box (default)
# SHORT_LAYOUT = "side"  # logo left, info right
```

---

# Example Output
### Full mode
$ secfetch
```
                   ____     __       __
   ________  _____/ __/__  / /______/ /_
  / ___/ _ \ / ___/ /_/ _ \/ __/ ___/ __ \
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
    ✔  LSM                     capability,landlock,lockdown,yama,bpf

  Kernel Hardening
  ────────────────────────────────────────
    ✖  kptr_restrict           Unrestricted
    ✔  dmesg_restrict          Enabled
    ✔  ptrace_scope            Restricted
    ⚠  modules_disabled        Disabled
    ✔  unprivileged_bpf        Permanently Disabled

  Network
  ────────────────────────────────────────
    ✖  Firewall                No firewall detected
    •  IPv6                    Enabled
    ⚠  Open Ports              53, 68
    ✔  Reverse Path Filter     Strict
    ✔  TCP SYN Cookies         Enabled

  Security Score
  ────────────────────────────────────────
    System                [░░░░░░░░░░░░]  0/100
    Kernel Security       [██████████░░]  85/100
    Kernel Hardening      [████████░░░░]  72/100
    Network               [██████░░░░░░]  55/100
  ────────────────────────────────────────
    Total                 [███████░░░░░]  64/100
```

### Short mode
$ secfetch --short

  ```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  System    Kernel: 6.19.6-arch1-1        Secure Boot: ✖ Disabled                                                   │
  │  Security  ASLR: ✔ Full         Lockdown: ⚠ none                                                          │
  │  Network   Firewall: ✖ No firewall detected  Ports: ⚠ 53, 68, 631, 1716, 5353, 5355, 32796, 43111, 48648  │
  │  Score     [█████████░░░░░░]  64/100                                                                               │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
The short mode is designed for use in .bashrc / .zshrc as a terminal startup overview.
The settings for the checks that can be performed in fastscan can be set to true/false in the config.conf file created for this purpose after starting secfetch for the first time.

---

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

## Project Structure

```
secfetch/ 
├── pyproject.toml
├── cli.py
├── README.md
├── LICENSE
├── __init__.py
├── src/ 
│ └── secfetch/ 
│ │ ├── checks/ 
│ │ │ ├── __init__.py
│ │ │ ├── kernel/ 
│ │ │ │ ├── __init__.py
│ │ │ │ ├── aslr.py 
│ │ │ │ ├── hardening.py 
│ │ │ │ ├── lockdown.py 
│ │ │ │ ├── kernel_version.py
│ │ │ │ └── lsm.py 
│ │ │ ├── network/ 
│ │ │ │ ├── __init__.py
│ │ │ │ ├──  firewall.py 
│ │ │ │ ├──  ipv6.py 
│ │ │ │ ├── rp_filter.py
│ │ │ │ ├── tcp_syncookies.py
│ │ │ │ └── ports.py 
│ │ │ └── system/ 
│ │ │ │ ├── __init__.py
│ │ │ │ └── secureboot.py 
│ │ ├── core/ 
│ │ │ ├── __init__.py
│ │ │ ├── check.py 
│ │ │ ├── loader.py 
│ │ │ ├── config.py
│ │ │ ├── registry.py
│ │ │ ├── runner.py
│ │ │ ├── scanner.py
│ │ │ └── scoring.py 
│ │ ├── ui/ 
│ │ │ ├── __init__.py
│ │ │ ├── help.py
└──  └── output.py 
```

---

## Roadmap

**v1.3**:
- Expansion of network checks --> risk assessment of open ports, firewall rules, active services.
- Compression of previously written code and naming of its functions using # comments.

**v2.0**:
- `secfetch deepscan` with extended checks, CVE lookups and detailed system fingerprinting.
- Adding secfetch to AUR

---

# License

This project is licensed under the **GNU General Public License v3.0 (GPL‑3.0)**.

See the [LICENSE](LICENSE) file for details.
