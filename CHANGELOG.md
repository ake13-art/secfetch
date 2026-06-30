## [1.8.0] - 30.06.2026

### Added

- **Phase 2 — four new secscan audit categories** (all run without root, using only world-readable `/proc/sys` and non-privileged `systemctl` queries; included in `secscan`, `--quick`, `--full`, and `--category <name>`):
  - **boot** — verifies the GRUB boot menu is password-protected (`set superusers` / `password_pbkdf2`, BOOT-5122) so an attacker at the console cannot drop to a root shell via `init=/bin/bash`; flags a world-readable GRUB password hash (BOOT-5121).
  - **kernel** — checks nine runtime sysctl hardening parameters: full ASLR (`randomize_va_space`), `kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, `fs.suid_dumpable`, `unprivileged_bpf_disabled`, `kernel.sysrq`, `kexec_load_disabled` and `perf_event_paranoid`. Parameters whose `/proc/sys` file is absent are skipped silently.
  - **services** — flags enabled systemd units that expose legacy/cleartext protocols (telnet, rsh, rlogin, rexec, tftp, vsftpd, NIS/yp, talk, finger, rpcbind) via `systemctl is-enabled` (SRV-3104).
  - **logging** — ensures a system logger is active (journald/rsyslog/syslog-ng, LOG-4001), that auditd is running (LOG-4010), and that journald persists logs across reboots (LOG-4031).
- **+27 tests** for the new categories; project coverage remains at **100 %**.

### Changed

- `engine._requires_root()` no longer gates `kernel`, `booting`, `services` or `logging`. The Phase 2 checks read only world-readable sources, so they now run for normal users instead of being silently skipped. Only `files` and `attributes` remain root-gated.
- `engine.run_quick_audit()` now includes the `boot` and `logging` categories (`kernel` and `services` were already listed).

## [1.7.0] - 08.06.2026

### Added

- **Four new secscan audit categories** (all run without root and are included in `secscan --quick`, `--full`, and `--category <name>`):
  - **authentication** — parses `/etc/login.defs` and flags weak `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE`, a weak `ENCRYPT_METHOD` (MD5/DES/SHA256), and a too-permissive `UMASK`.
  - **firewall** — best-effort, non-interactive detection of an active firewall (firewalld / ufw / nftables / iptables via `systemctl is-active`, `ufw status`, `nft list ruleset`); reports a finding when none is active.
  - **cron** — flags world-writable `/etc/crontab`, cron directories and the files inside them, plus a missing `cron.allow`/`cron.deny` policy.
  - **permissions** — checks mode and root ownership of `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` using `os.stat` (metadata only, so it works as a normal user).
- **`secfetch --short` fastfetch-style layout** — logo left, `user@hostname` header right, blue labels, status-coloured values. Set `logo = arch | debian | ubuntu | fedora | none` in `~/.config/secfesc/checks.conf` to match your distro.
- **+130 tests** (226 → 356 total); coverage raised from 93 % to **100 %**.

### Changed

- `engine._requires_root()` no longer gates the `permissions` category — its checks rely on `os.stat` metadata, which any user can read.
- **`checks/network/ipv6.py`**: IPv6 enabled now returns `status: warn` instead of `status: info`. IPv6 being on is a hardening consideration (partial credit, 5/10), not neutral (0/10). This is consistent with how other "suboptimal but not dangerous" states are handled (e.g. `rp_filter` Loose = warn).

### Fixed

- **`checks/network/firewall.py`**: Added `_firewalld_active()` helper that detects firewalld via `systemctl is-active firewalld` (no sudo/polkit required). firewalld is now checked first before falling back to ufw / nftables / iptables. Previously, all backends called `sudo` unconditionally, triggering polkit authentication prompts on every secfetch run.
- **`checks/network/ports.py`**: Open ports check now returns `status: ok` instead of `status: info` when all listening ports are expected (risk priority below warn threshold). The `info` status contributed 0 points to the security score, causing the score to paradoxically *drop* when a previously-warned port was closed.
- **`secfetch/data/port_db.py`**: Ephemeral/dynamic ports (49152+) were classified with risk `"info"`, which is absent from `RISK_COLORS` and fell back to yellow (warning colour). They are now classified as `"expected"` and display green.
- **`secscan/cli.py`** + **`secscan/report/html.py`**: Version string was hardcoded as `"secscan 1.7.0"` and would drift out of sync with `pyproject.toml` on every release. Both now read the version dynamically via `importlib.metadata.version("secfesc")`.
- **`secscan/core/registry.py`**: `_discover()` lacked a threading lock on the `_discovered` flag, unlike the equivalent function in `shared/registry.py`. Added `_discover_lock` for consistency and correctness.
- **`secscan/cli.py`**: Removed an unreachable `else` branch in the report-format dispatch (argparse `choices=` already enforces valid formats; the branch could never be reached).
- **`secscan/report/html.py`**: Finding fields (`title`, `description`, `solution`, `affected`, `category`, `severity`) were inserted into the HTML report without escaping. Special characters in system data (e.g. a username containing `<` from `/etc/passwd`) would corrupt the output. All fields are now passed through `html.escape()`. Also added the `affected` field to finding cards (it was rendered in the terminal summary but omitted from the HTML output).

### Code Quality

- **`shared/types.py`**: Removed Python 3.7 compatibility shim (`try/except ImportError` for `TypedDict`). `pyproject.toml` declares `requires-python = ">=3.8"` where `TypedDict` ships in `typing` natively.
- **`secfetch/ui/help.py`**: Fixed stale help text `"(see config.py)"` → correct reference to `~/.config/secfesc/checks.conf`.

## [1.6.1] - 03.06.2026

Quality & consistency release — no new checks, a healthier foundation.

### Changed

- ASCII banner now reads **secfesc** (instead of the old "secfetch") in `README.md` and the in-tool logo (`output.py` `LOGO_FULL`/`LOGO_SHORT`).
- Renamed the persisted sysctl auto-fix file from `99-secfetch.conf` to `99-secfesc.conf` for naming consistency. An existing `99-secfetch.conf` stays active until you remove it.

### Removed

- Dead code: the unused `shared/help.py` duplicate (secfetch uses `secfetch/ui/help.py`) and the empty `secfetch/export/` stub.

### Fixed

- `engine.py`: `_requires_root()` referenced a `boot` category that does not exist; aligned it to the real category name `booting`.

### Tests

- Added tests for the secscan report exporters (`json`/`html`/`csv`) — previously untested — and smoke tests for secfetch/secscan output rendering.
- Overall coverage raised from 75% to 80% (226 tests).

## [1.6.0] - 03.06.2026

### Added

- **secscan now produces real findings.** Implemented a shared audit-check framework and the Phase 1 categories from the roadmap:
  - `secscan/core/registry.py`: `@audit_check(category)` decorator, auto-discovery of `secscan/core/categories/`, and a per-category runner that turns check functions into `AuditFinding`s (a failing check degrades to an error finding instead of aborting the audit).
  - `checks ssh`: PermitRootLogin, PermitEmptyPasswords, PasswordAuthentication, legacy Protocol 1, X11Forwarding, MaxAuthTries — reads effective config via `sshd -T` (root) with a `/etc/ssh/sshd_config` fallback and OpenSSH defaults for absent directives.
  - `checks users`: non-root UID 0 accounts, duplicate UIDs, duplicate usernames, and empty passwords (via `/etc/shadow` when run as root).
  - `checks groups`: duplicate GIDs, duplicate group names, and extra members of the root group.
  - Milestone reached: `secscan --category ssh` returns real findings.
- secscan output now lists every finding grouped by category (coloured by severity, with affected item and remediation), plus an error/warning/note breakdown in the summary.
- secscan reports skipped categories (e.g. root-only ones run without root) as warnings in the summary and exports.
- HTML report: added an **Errors** summary card (the `error_count` was previously computed but never shown).
- Tests: added `tests/test_secscan.py` (17 tests) covering the registry, ssh/users/groups checks, and engine integration.

### Changed

- **Packaging fix (breaking-internal):** completed the migration from the legacy top-level `secfetch` package to the `secfesc` umbrella. The whole codebase and test suite now import from `secfesc.*`; the project is installable and self-contained (previously it only ran because an older `secfetch` package happened to be installed globally).
- **Unified check framework:** the `@security_check` decorator, registry, discovery and parallel runner now live in `secfesc/shared/registry.py` and are shared infrastructure; secfetch renders results compactly while secscan renders a deep audit.
- Cross-cutting utilities (types, config, colors, logger, error handling, scoring) are now sourced solely from `secfesc/shared/`; the duplicated `secfetch/core/` copies were removed.
- `secscan --report <fmt>` written to stdout no longer prints the human summary first, so the JSON/CSV/HTML stream is clean and machine-parseable. With `--output FILE`, the summary is still shown.
- `secscan --full` now runs every category that has implemented checks (instead of scaffolding all ~55 planned categories and finding nothing).

### Fixed

- `engine.py`: removed the leading-space typo in the `"cryptographic"` category name.

### Docs

- `/docs` is now a GitHub Pages site (Jekyll config + landing page) so the documentation renders as a site when Pages is pointed at the `docs/` folder.

## [1.5.3] - 13.04.2026

### Added

- `secscan` report export: JSON, HTML, and CSV formats
- `--output FILE` argument to write export to file instead of stdout

### Fixed

- `output.py`: Removed duplicate `_strip_ansi()` function definition
- `engine.py`: Thread safety in `_discover_checks()` - flag set only after loading completes (prevents retry on partial failure)
- `secscan/cli.py`: Version bump to 1.5.3

### Code Quality

- Consolidated export functionality into `secscan/report/` module (json.py, html.py, csv.py)

## [1.5.2] - 13.04.2026

### Fixed

- `engine.py`: Fix "2>/dev/null" passed as literal arg to find (use stderr=DEVNULL)
- `config.py`: Fix duplicate config keys overriding fastscan defaults
- `network.py`: Remove redundant full GET in _has_network(), use direct download with fallback
- `improve.py`: Fix silent sysctl persistence failure and duplicate config entries
- `port_db.py`: Fix inconsistent "warn" risk level (now "unknown")
- `port_db.py`: Fix race condition in background update (atomic dict replace)
- `firewall.py`: Add @handle_check_errors decorator to firewall check
- `services.py`: Deduplicate SUSPICIOUS_SERVICES via import

### Maintenance

- Add `.claude/` to `.gitignore`

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
