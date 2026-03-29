import shutil
import subprocess
from pathlib import Path

from secfetch.ui.help import CHECK_DESCRIPTIONS

SYSCTL_FILE = "/etc/sysctl.d/99-secfetch.conf"

SYSCTL_PERSISTENT = {
    "aslr": ("kernel.randomize_va_space", "2"),
    "kptr_restrict": ("kernel.kptr_restrict", "2"),
    "dmesg_restrict": ("kernel.dmesg_restrict", "1"),
    "ptrace_scope": ("kernel.yama.ptrace_scope", "1"),
    "modules_disabled": ("kernel.modules_disabled", "1"),
    "unprivileged_bpf": ("kernel.unprivileged_bpf_disabled", "2"),
    "ipv6": ("net.ipv6.conf.all.disable_ipv6", "1"),
    "tcp_syn_cookies": ("net.ipv4.tcp_syncookies", "1"),
    "reverse_path_filter": ("net.ipv4.conf.all.rp_filter", "1"),
}

AUTO_FIXES = {
    "aslr": [["sudo", "sysctl", "-w", "kernel.randomize_va_space=2"]],
    "kptr_restrict": [["sudo", "sysctl", "-w", "kernel.kptr_restrict=2"]],
    "dmesg_restrict": [["sudo", "sysctl", "-w", "kernel.dmesg_restrict=1"]],
    "ptrace_scope": [["sudo", "sysctl", "-w", "kernel.yama.ptrace_scope=1"]],
    "modules_disabled": [["sudo", "sysctl", "-w", "kernel.modules_disabled=1"]],
    "unprivileged_bpf": [["sudo", "sysctl", "-w", "kernel.unprivileged_bpf_disabled=2"]],
    "ipv6": [["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"]],
    "tcp_syn_cookies": [["sudo", "sysctl", "-w", "net.ipv4.tcp_syncookies=1"]],
    "reverse_path_filter": [["sudo", "sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"]],
    "/tmp_sticky_bit": [["sudo", "chmod", "+t", "/tmp"]],
    "firewall": [["sudo", "ufw", "enable"]],
}

RISKY_FIXES = {
    "modules_disabled": "Irreversible until reboot! No new kernel modules can be loaded.",
}

SUSPICIOUS_SERVICES = {
    "telnetd", "rshd", "rlogind", "ftpd", "vsftpd", "proftpd", "xinetd", "inetd", "rpcbind"
}


RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _divider():
    print("  " + "─" * 56)


def print_improve(results: list[dict]) -> None:
    failed = [r for r in results if r["status"] in ("bad", "warn")]

    if not failed:
        print("\n  ✔  All checks passed – nothing to improve.\n")
        return

    firewall_available = _check_firewall_available()
    fixable_count = 0

    print(f"\n  {len(failed)} issue(s) found\n")

    for r in failed:
        key = r["name"].lower().replace(" ", "_")
        info = CHECK_DESCRIPTIONS.get(key, {})
        risk = info.get("risk", "?")
        fix = info.get("fix", "No fix available.")

        icon = "✖" if r["status"] == "bad" else "⚠"

        is_auto_fixable = key in AUTO_FIXES
        if key == "firewall" and not firewall_available:
            is_auto_fixable = False
            fix = "Install ufw: sudo apt install ufw && sudo ufw enable"

        auto_tag = f"  {GREEN}[auto-fixable]{RESET}" if is_auto_fixable else ""

        if is_auto_fixable:
            fixable_count += 1

        print(f"  {icon}  {r['name']:<22}  Risk: {risk}{auto_tag}")
        print(f"     Fix: {fix}")
        print()

    if fixable_count > 0:
        print(f"  {fixable_count} issue(s) can be auto-fixed.")
        print(f"  Run {CYAN}secfetch improve --auto{RESET} to select and apply fixes.\n")


def apply_fixes(results: list[dict]) -> None:
    failed = [r for r in results if r["status"] in ("bad", "warn")]

    firewall_available = _check_firewall_available()

    fixable = []
    for r in failed:
        key = r["name"].lower().replace(" ", "_")

        if key == "firewall" and not firewall_available:
            continue

        if key in AUTO_FIXES:
            fixable.append({
                "name": r["name"],
                "key": key,
                "cmds": list(AUTO_FIXES[key]),
                "risky": key in RISKY_FIXES,
                "selected": key not in RISKY_FIXES,
            })

    manual_only = [r for r in failed if r["name"].lower().replace(" ", "_") not in AUTO_FIXES]

    if not firewall_available:
        firewall_failed = next((r for r in failed if r["name"].lower().replace(" ", "_") == "firewall"), None)
        if firewall_failed:
            manual_only.append(firewall_failed)

    services = _extract_suspicious_services(results)
    if services:
        fixable.append({
            "name": "Suspicious Services",
            "key": "services",
            "services": list(services),
            "cmds": [["sudo", "systemctl", "disable", "--now", s] for s in services],
            "risky": False,
            "selected": True,
        })

    if not fixable:
        if failed:
            print(f"\n  {len(failed)} issue(s) found, but none are auto-fixable.")
            print(f"  Run {CYAN}secfetch improve{RESET} for manual fix suggestions.\n")
        else:
            print("\n  ✔  All checks passed – nothing to fix.\n")
        return

    while True:
        print(f"\n  {BOLD}Auto-Fix  —  secfetch improve --auto{RESET}")
        _divider()
        print()

        for i, f in enumerate(fixable):
            num = f"{i + 1}"
            check = f"[{GREEN}✔{RESET}]" if f["selected"] else f"[{RED}✖{RESET}]"

            if f["key"] == "services":
                svc_str = ", ".join(f["services"])
                print(f"    [{num}] {check}  {f['name']:<22}  disable {svc_str}")
            else:
                cmd_str = "  ".join(" ".join(cmd) for cmd in f["cmds"])
                print(f"    [{num}] {check}  {f['name']:<22}  {cmd_str}")

            if f["risky"]:
                print(f"         {YELLOW}⚠  {RISKY_FIXES[f['key']]}{RESET}")

        if manual_only:
            print()
            _divider()
            print(f"  {BOLD}Require manual fix{RESET}  —  run {CYAN}secfetch improve{RESET} for details:")
            print()
            for r in manual_only:
                icon = "✖" if r["status"] == "bad" else "⚠"
                print(f"    {icon}  {r['name']:<22}  {r['value']}")

        print()
        _divider()

        selected_count = sum(1 for f in fixable if f["selected"])
        print(f"\n  {selected_count} fix(es) selected.")
        print(f"  Toggle: {CYAN}1-{len(fixable)}{RESET} | {CYAN}a{RESET} = all | {CYAN}n{RESET} = none | {CYAN}Enter{RESET} = confirm | {CYAN}q{RESET} = quit")

        try:
            choice = input("\n  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.")
            return

        if choice == "q":
            print("  Aborted.")
            return

        if choice == "":
            break

        if choice == "a":
            for f in fixable:
                f["selected"] = True
            continue

        if choice == "n":
            for f in fixable:
                f["selected"] = False
            continue

        nums = choice.replace(",", " ").split()
        for n in nums:
            try:
                idx = int(n) - 1
                if 0 <= idx < len(fixable):
                    f = fixable[idx]
                    f["selected"] = not f["selected"]
                    if f["selected"] and f["risky"]:
                        print(f"\n  {YELLOW}⚠  Warning: {RISKY_FIXES[f['key']]}{RESET}")
            except ValueError:
                pass

    selected = [f for f in fixable if f["selected"]]

    if not selected:
        print("  Nothing selected. Aborted.")
        return

    print("\n  The following commands will be executed:\n")
    for f in selected:
        if f["key"] == "services":
            for svc in f["services"]:
                print(f"    sudo systemctl disable --now {svc}")
        else:
            for cmd in f["cmds"]:
                print(f"    {' '.join(cmd)}")
            if f["risky"]:
                print(f"    {YELLOW}⚠  {RISKY_FIXES[f['key']]}{RESET}")
    print()

    try:
        answer = input("  Proceed? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  Aborted.")
        return

    if answer != "y":
        print("  Aborted.")
        return

    print()
    _apply_persistent_sysctl_config()

    for f in selected:
        if f["key"] == "services":
            for svc in f["services"]:
                print(f"  → sudo systemctl disable --now {svc}")
                _run_command(["sudo", "systemctl", "disable", "--now", svc])
        else:
            for cmd in f["cmds"]:
                print(f"  → {' '.join(cmd)}")
                _run_command(cmd)

            if f["key"] in SYSCTL_PERSISTENT and f["selected"]:
                param, val = SYSCTL_PERSISTENT[f["key"]]
                _write_sysctl_config(param, val)
                print(f"    {GREEN}✓ Persisted to {SYSCTL_FILE}{RESET}")

    print()


def _extract_suspicious_services(results: list[dict]) -> set:
    for r in results:
        if r["name"].lower() == "services":
            value = r.get("value", "")
            found = set()
            for svc in SUSPICIOUS_SERVICES:
                if svc in value:
                    found.add(svc)
            return found
    return set()


def _write_sysctl_config(param: str, value: str) -> None:
    try:
        Path(SYSCTL_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(SYSCTL_FILE, "a") as f:
            f.write(f"{param} = {value}\n")
    except PermissionError:
        pass


def _apply_persistent_sysctl_config() -> None:
    if Path(SYSCTL_FILE).exists():
        print(f"  Applying persistent settings from {SYSCTL_FILE}...")
        _run_command(["sudo", "sysctl", "-p", SYSCTL_FILE])


def _check_firewall_available() -> bool:
    if shutil.which("ufw"):
        return True
    if shutil.which("firewalld"):
        return True
    if shutil.which("iptables"):
        return True
    return False


def _run_command(cmd: list) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"    {GREEN}✔ Applied{RESET}")
            return True
        else:
            err = result.stderr.strip() or "Unknown error"
            print(f"    {RED}✖ Failed: {err}{RESET}")
            return False
    except subprocess.TimeoutExpired:
        print(f"    {RED}✖ Failed: Command timeout (30s){RESET}")
    except FileNotFoundError:
        cmd_name = cmd[0] if cmd else "unknown"
        if cmd_name == "ufw":
            print(f"    {RED}✖ Failed: ufw not installed. Install with: sudo apt install ufw{RESET}")
        else:
            print(f"    {RED}✖ Failed: Command not found{RESET}")
    except Exception as e:
        print(f"    {RED}✖ Failed: {str(e)}{RESET}")
    return False

