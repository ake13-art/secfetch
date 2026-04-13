from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from secfetch.checks.network.services import SUSPICIOUS as SUSPICIOUS_SERVICES
from secfetch.core.types import CheckResult, FixItem
from secfetch.data.fixes import AUTO_FIXES, RISKY_FIXES, SYSCTL_FILE, SYSCTL_PERSISTENT
from secfetch.ui.colors import BOLD, CYAN, GREEN, RED, RESET, YELLOW
from secfetch.ui.help import CHECK_DESCRIPTIONS

_CMD_TIMEOUT = 30  # seconds for each apply command

# Pre-computed for _extract_suspicious_services
_SUSPICIOUS_SERVICES_LOWER: frozenset[str] = frozenset(s.lower() for s in SUSPICIOUS_SERVICES)


def _divider() -> None:
    print("  " + "─" * 56)


def print_improve(results: list[CheckResult]) -> None:
    """Print a summary of failed checks with fix suggestions and auto-fixable tags."""
    failed = [result for result in results if result["status"] in ("bad", "warn")]

    if not failed:
        print("\n  ✔  All checks passed – nothing to improve.\n")
        return

    firewall_available = _check_firewall_available()
    fixable_count = 0

    print(f"\n  {len(failed)} issue(s) found\n")

    for result in failed:
        key = result["name"].lower().replace(" ", "_")
        info = CHECK_DESCRIPTIONS.get(key, {})
        risk = info.get("risk", "?")
        fix = info.get("fix", "No fix available.")

        icon = "✖" if result["status"] == "bad" else "⚠"

        is_auto_fixable = key in AUTO_FIXES
        if key == "firewall_rules" and not firewall_available:
            is_auto_fixable = False
            fix = "Install ufw: sudo apt install ufw && sudo ufw enable"

        auto_tag = f"  {GREEN}[auto-fixable]{RESET}" if is_auto_fixable else ""

        if is_auto_fixable:
            fixable_count += 1

        print(f"  {icon}  {result['name']:<22}  Risk: {risk}{auto_tag}")
        print(f"     Fix: {fix}")
        print()

    if fixable_count > 0:
        print(f"  {fixable_count} issue(s) can be auto-fixed.")
        print(f"  Run {CYAN}secfetch improve --auto{RESET} to select and apply fixes.\n")


def _select_fixes(fixable: list[FixItem], manual_only: list[CheckResult]) -> list[FixItem] | None:
    """Run the interactive selection loop. Returns selected items or None if the user aborted."""
    while True:
        print(f"\n  {BOLD}Auto-Fix  —  secfetch improve --auto{RESET}")
        _divider()
        print()

        for i, fix_item in enumerate(fixable):
            num = f"{i + 1}"
            check = f"[{GREEN}✔{RESET}]" if fix_item["selected"] else f"[{RED}✖{RESET}]"

            if fix_item["key"] == "services":
                svc_str = ", ".join(fix_item["services"])
                print(f"    [{num}] {check}  {fix_item['name']:<22}  disable {svc_str}")
            else:
                cmd_str = "  ".join(" ".join(cmd) for cmd in fix_item["cmds"])
                print(f"    [{num}] {check}  {fix_item['name']:<22}  {cmd_str}")

            if fix_item["risky"]:
                print(f"         {YELLOW}⚠  {RISKY_FIXES[fix_item['key']]}{RESET}")

        if manual_only:
            print()
            _divider()
            print(
                f"  {BOLD}Require manual fix{RESET}  —  run {CYAN}secfetch improve{RESET} for details:"
            )
            print()
            for result in manual_only:
                icon = "✖" if result["status"] == "bad" else "⚠"
                print(f"    {icon}  {result['name']:<22}  {result['value']}")

        print()
        _divider()

        selected_count = sum(1 for fix_item in fixable if fix_item["selected"])
        print(f"\n  {selected_count} fix(es) selected.")
        print(
            f"  Toggle: {CYAN}1-{len(fixable)}{RESET} | {CYAN}a{RESET} = all | {CYAN}n{RESET} = none | {CYAN}Enter{RESET} = confirm | {CYAN}q{RESET} = quit"
        )

        try:
            choice = input("\n  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.")
            return None

        if choice == "q":
            print("  Aborted.")
            return None

        if choice == "":
            return [fix_item for fix_item in fixable if fix_item["selected"]]

        if choice == "a":
            for fix_item in fixable:
                fix_item["selected"] = True
            continue

        if choice == "n":
            for fix_item in fixable:
                fix_item["selected"] = False
            continue

        nums = choice.replace(",", " ").split()
        invalid = []
        for n in nums:
            try:
                idx = int(n) - 1
                if 0 <= idx < len(fixable):
                    fix_item = fixable[idx]
                    fix_item["selected"] = not fix_item["selected"]
                    if fix_item["selected"] and fix_item["risky"]:
                        print(f"\n  {YELLOW}⚠  Warning: {RISKY_FIXES[fix_item['key']]}{RESET}")
            except ValueError:
                invalid.append(n)
        if invalid:
            print(f"  Invalid input ignored: {', '.join(invalid)}")


def _build_fixable_list(
    failed: list[CheckResult],
    firewall_available: bool,
    suspicious_services: set[str],
) -> tuple[list[FixItem], list[CheckResult]]:
    """Classify failed checks into auto-fixable and manual-only lists."""
    fixable: list[FixItem] = []
    for result in failed:
        key = result["name"].lower().replace(" ", "_")
        if key == "firewall_rules" and not firewall_available:
            continue
        if key in AUTO_FIXES:
            fixable.append(
                {
                    "name": result["name"],
                    "key": key,
                    "cmds": list(AUTO_FIXES[key]),
                    "risky": key in RISKY_FIXES,
                    "selected": key not in RISKY_FIXES,
                    "services": [],
                }
            )

    manual_only = [
        result for result in failed if result["name"].lower().replace(" ", "_") not in AUTO_FIXES
    ]
    if not firewall_available:
        fw = next(
            (
                result
                for result in failed
                if result["name"].lower().replace(" ", "_") == "firewall_rules"
            ),
            None,
        )
        if fw:
            manual_only.append(fw)

    if suspicious_services:
        fixable.append(
            {
                "name": "Suspicious Services",
                "key": "services",
                "cmds": [["sudo", "systemctl", "disable", "--now", s] for s in suspicious_services],
                "risky": False,
                "selected": True,
                "services": list(suspicious_services),
            }
        )

    return fixable, manual_only


def apply_fixes(results: list[CheckResult]) -> None:
    """Interactive auto-fix wizard: classify issues, let the user select, then apply."""
    failed = [result for result in results if result["status"] in ("bad", "warn")]
    firewall_available = _check_firewall_available()
    services = _extract_suspicious_services(results)
    fixable, manual_only = _build_fixable_list(failed, firewall_available, services)

    if not fixable:
        if failed:
            print(f"\n  {len(failed)} issue(s) found, but none are auto-fixable.")
            print(f"  Run {CYAN}secfetch improve{RESET} for manual fix suggestions.\n")
        else:
            print("\n  ✔  All checks passed – nothing to fix.\n")
        return

    selected = _select_fixes(fixable, manual_only)

    if selected is None:
        return
    if not selected:
        print("  Nothing selected. Aborted.")
        return

    print("\n  The following commands will be executed:\n")
    for fix_item in selected:
        if fix_item["key"] == "services":
            for svc in fix_item["services"]:
                print(f"    sudo systemctl disable --now {svc}")
        else:
            for cmd in fix_item["cmds"]:
                print(f"    {' '.join(cmd)}")
            if fix_item["risky"]:
                print(f"    {YELLOW}⚠  {RISKY_FIXES[fix_item['key']]}{RESET}")
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

    sysctl_applied = False

    for fix_item in selected:
        if fix_item["key"] == "services":
            for svc in fix_item["services"]:
                print(f"  → sudo systemctl disable --now {svc}")
                _run_command(["sudo", "systemctl", "disable", "--now", svc])
        else:
            for cmd in fix_item["cmds"]:
                print(f"  → {' '.join(cmd)}")
                _run_command(cmd)

            if fix_item["key"] in SYSCTL_PERSISTENT and fix_item["selected"]:
                param, val = SYSCTL_PERSISTENT[fix_item["key"]]
                if _write_sysctl_config(param, val):
                    sysctl_applied = True
                    print(f"    {GREEN}✓ Persisted to {SYSCTL_FILE}{RESET}")
                else:
                    print(
                        f"    {YELLOW}⚠ Could not persist to {SYSCTL_FILE} (permission denied){RESET}"
                    )

    if sysctl_applied:
        _apply_persistent_sysctl_config()
    print()


def _extract_suspicious_services(results: list[CheckResult]) -> set[str]:
    """Extract suspicious service names from the Services check result.

    Parses the value field which has format: "N running, suspicious: svc1, svc2"
    or "N running, unnecessary: svc1, svc2".
    """
    for result in results:
        if result["name"].lower() == "services":
            value = result.get("value", "")
            if ":" not in value:
                return set()
            _, after_colon = value.split(":", 1)
            mentioned = {s.strip() for s in after_colon.split(",") if s.strip()}
            return {s for s in mentioned if s.lower() in _SUSPICIOUS_SERVICES_LOWER}
    return set()


def _write_sysctl_config(param: str, value: str) -> bool:
    try:
        sysctl_path = Path(SYSCTL_FILE)
        sysctl_path.parent.mkdir(parents=True, exist_ok=True)

        # Read existing content to avoid duplicates
        existing = sysctl_path.read_text() if sysctl_path.exists() else ""
        lines = existing.splitlines()

        # Update existing param or append new one
        updated = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(f"{param} ") or stripped.startswith(f"{param}="):
                lines[i] = f"{param} = {value}"
                updated = True
                break

        if not updated:
            lines.append(f"{param} = {value}")

        while lines and not lines[-1].strip():
            lines.pop()

        sysctl_path.write_text("\n".join(lines) + "\n")
        return True
    except PermissionError:
        return False


def _apply_persistent_sysctl_config() -> None:
    if Path(SYSCTL_FILE).exists():
        print(f"  Applying persistent settings from {SYSCTL_FILE}...")
        _run_command(["sudo", "sysctl", "-p", SYSCTL_FILE])


def _check_firewall_available() -> bool:
    """Return True if at least one supported firewall tool (ufw, firewalld, iptables) is installed."""
    return bool(shutil.which("ufw") or shutil.which("firewalld") or shutil.which("iptables"))


def _run_command(cmd: list[str]) -> bool:
    """Run a shell command list and print success/failure. Returns True on success."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_CMD_TIMEOUT)
        if result.returncode == 0:
            print(f"    {GREEN}✔ Applied{RESET}")
            return True
        else:
            err = result.stderr.strip() or "Unknown error"
            print(f"    {RED}✖ Failed: {err}{RESET}")
            return False
    except subprocess.TimeoutExpired:
        print(f"    {RED}✖ Failed: Command timeout ({_CMD_TIMEOUT}s){RESET}")
    except FileNotFoundError:
        cmd_name = cmd[0] if cmd else "unknown"
        if cmd_name == "ufw":
            print(
                f"    {RED}✖ Failed: ufw not installed. Install with: sudo apt install ufw{RESET}"
            )
        else:
            print(f"    {RED}✖ Failed: Command not found{RESET}")
    except Exception as e:
        print(f"    {RED}✖ Failed: {str(e)}{RESET}")
    return False
