## [1.5.1] - 29.03.2026

### Fixed

- `engine.py`: Fixed syntax error in `raw.update()` call (missing parentheses for dict)
- `ports.py`: Duplicate port check now considers protocol (TCP vs UDP)
- `port_db.py`: Fixed protocol handling for empty protocol fields in IANA CSV
- Firewall checks now use `sudo` for ufw, iptables, and nft commands to avoid permission denied errors when running as non-root user

### Code Quality

- Fixed all remaining lint errors (trailing whitespace, ambiguous variable names, import sorting)
- Replaced ambiguous variable `l` with descriptive `line` in firewall.py and output.py

## [1.5.0] - 27.03.2026

### Added

- `secfetch improve` command: shows all failed checks with fix suggestions
- `secfetch improve --auto` command: interactive auto-fix selection with toggle UI
- Risky fix warnings (e.g. `modules_disabled` flagged as irreversible)
- Manual-only fix section in auto-fix view
- **Persistent sysctl fixes**: Auto-fixes now write to `/etc/sysctl.d/99-secfetch.conf` for reboot persistence
- **Service auto-fix**: Suspicious services (telnetd, rshd, ftpd, etc.) can be auto-disabled
- **Firewall availability check**: Only offers firewall fix if ufw/firewalld/iptables is installed

### Changed

- Services check: replaced whitelist approach with blacklist of suspicious/unnecessary services
- Services now flags known-risky services (e.g. telnetd, rshd) and unnecessary ones (e.g. cups, bluetooth)
- Reduced false positives for services check significantly
- Firewall check: improved detection for ufw, firewalld, nftables, and iptables
- Firewall help text: now includes installation instructions for ufw
- `improve` output: shows install instructions when firewall tool is not available

### Fixed

- `improve.py`: AUTO_FIXES key mismatch - keys now use underscores instead of spaces
- `improve.py`: Fixed `fixable_count` calculation (was not normalizing keys)
- `improve.py`: Fixed risky fix warning for `modules_disabled`
- `improve.py`: Removed unused imports (`shlex`, `sys`)
- `help.py`: Added missing CHECK_DESCRIPTIONS entries for `firewall_rules`, `tcp_syn_cookies`, `reverse_path_filter`
- Services check no longer flags nearly all running services as unexpected
- Services help description updated to match blacklist logic
- `secfetch improve` and `secfetch improve --auto` added to help output
- `--auto` flag was passing `auto=False` to `apply_fixes`; removed unused parameter
- `ipv6.py`: Added `@handle_check_errors` decorator for consistent error handling
- `tcp_syncookies.py`: Added `@handle_check_errors` decorator
- `rp_filter.py`: Added `@handle_check_errors` decorator
- `lockdown.py`: Added `@handle_check_errors` decorator

### Security

- Improved input sanitization in `improve --auto` command selection
- Command execution uses arrays instead of shell strings (prevents injection)
- Proper error handling for subprocess timeouts and missing commands

## [1.4.0] - 11.03.2026

### Added

- `secfetch live` command for continuous monitoring with auto-refresh
- `--interval` flag to set refresh rate in seconds (default: 5)
- Press `Q + Enter` to cleanly stop live monitoring (replaces Ctrl+C)

### Changed

- Live output now clears terminal and reprints on each cycle
- Moved from signal-based stop to threaded input listener for cleaner exit

## [1.3.1] - 11.03.2026

### Bugfix

- `Ports`: fixed broken indentation throughout ports.py caused by duplicate code blocks; continue statement not on its own line, if-block was outside the for-loop
- `CLI`: moved os.environ["SECFETCH_SHORT"] = "1" to before run_checks() so ports.py can read the flag at scan time
- `Output`: removed os import and SECFETCH_SHORT env (responsibility moved to cli.py)

## [1.3.0] - 11.03.2026

### Added

- `checks/network/services.py`: Active systemd service detection with risk classification for unexpected services
- `checks/network/firewall_rules.py`: Rule count and detail display for ufw, nftables and iptables
- `port_db.py`: IANA-based port database with local CSV cache, background update thread and offline fallback
- Port risk classification: `expected`, `unnecessary`, `suspicious`, `unknown`
- `help.py`: Added entries for `firewall rules`, `services`, `tcp_syncookies`, `rp_filter`
- `config.py`: Added `firewall_rules` and `services` (both disabled by default)
- Code comments throughout for improved readability

### Changed

- `firewall.py`: Now displays active rule count alongside firewall status
- `ports.py`: Open ports resolved to service names via `port_db`
- `ports.py`: Risk-based status (`critical`/`warn`/`info`/`ok`) replaces fixed threshold
- `ports.py`: Output now includes service name and protocol (e.g. `22 (SSH/TCP)`)
- `output.py`: Port color codes no longer overwritten by status colorizer
- `cli.py`: Removed duplicate code block, added `port_db.initialize()` on startup, comments cleaned up
- Codebase compressed – removed unnecessary verbosity across multiple modules

### Notes

- Deep Scan feature is in development and will ship with v2.0

## [1.2.0] – 10.03.2026

### Added

- Improved firewall backend detection: ufw, firewalld, nftables, iptables
- New check: TCP SYN Cookies (`/proc/sys/net/ipv4/tcp_syncookies`)
- New check: Reverse Path Filter (`/proc/sys/net/ipv4/conf/all/rp_filter`)
- Config system (`~/.config/secfetch/checks.conf`) – enable/disable checks
- Fastscan profile: only fast, non-intrusive checks run by default
- `output.py` fully rewritten – cleaner layout, box and side mode

### Changed

- `firewall.py` now tries multiple backends instead of ufw only
- `config.py` separates fastscan and fullscan checks clearly

### Notes

- Filesystem deep scan (world writable files, SUID binaries) is intentionally excluded from all scan modes. It will ship with the full **v2.0 Deep Scan** release to avoid long startup times and intrusive filesystem traversal.

------

## [1.1.0] – 09.03.2026

### Added

- Modular check system via `@security_check` decorator
- Checks: ASLR, Secure Boot, Kernel, Lockdown, kptr_restrict, dmesg_restrict, ptrace_scope, modules_disabled, bpf_hardening, Firewall, IPv6, Open Ports
- `help.py` with per-check descriptions, risk levels and fix hints
- Score system with color-coded bar
- Short output mode (box + side layout)

### Fixed

- Various formatting issues in `output.py`
- Linting fixes across all modules

------

## [1.0.0] – 08.03.2026

### Added

- Kernel security features
- Kernel hardening parameters
- Linux Security Modules
- Secure Boot status
- Firewall state
- Open network ports
- IPv6 configuration
