import argparse
from .system import get_kernel_version, check_secure_boot
from .kernel import check_aslr, check_lockdown, check_lsm
from .ui import color, Color, ICONS, status_color
from .helptext import CHECK_HELP
from .hardening import (
    check_kptr_restrict,
    check_dmesg_restrict,
    check_ptrace_scope,
    check_modules_disabled,
    check_unprivileged_bpf,
)
from .network import check_open_ports, check_ipv6
from .firewall import status_firewall

LOGO = r"""
                   ____     __       __  
   ________  _____/ __/__  / /______/ /_ 
  / ___/ _ \/ ___/ /_/ _ \/ __/ ___/ __ \
 (__  )  __/ /__/ __/  __/ /_/ /__/ / / /
/____/\___/\___/_/  \___/\__/\___/_/ /_/ 
"""


def parse_args():

    parser = argparse.ArgumentParser(
        prog="secfetch",
        description="Display system security information",
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("run", help="run security checks")

    help_parser = subparsers.add_parser("help", help="show explanation for a check")
    help_parser.add_argument("check", help="name of the check")

    parser.add_argument("-s", "--short", action="store_true", help="short overview")
    parser.add_argument("-d", "--deep", action="store_true", help="deep scan")
    parser.add_argument("-v", "--version", action="store_true", help="show version")

    return parser.parse_args()


def section(icon, title):

    header = f"{icon} {title}"

    print()
    print(f"{Color.CYAN}{header}{Color.RESET}")
    print(f"{Color.CYAN}{'-' * len(header)}{Color.RESET}")


def line(label, value):

    label = f"{Color.WHITE}{label:<20}{Color.RESET}"
    value = status_color(value)

    print(f"{label} {value}")


def main():

    args = parse_args()

    if args.version:
        print("secfetch 0.1")
        return

    if args.command == "help":
        name = args.check.lower()

        if name in CHECK_HELP:
            print(f"{name.upper()}\n")
            print(CHECK_HELP[name])
        else:
            print("Unknown check")
        return

    print(color(LOGO, Color.MAGENTA))

    section(ICONS["system"], "System")
    line("Kernel", get_kernel_version())
    line("Secure Boot", check_secure_boot())

    section(ICONS["kernel"], "Kernel Security")
    line("ASLR", check_aslr())
    line("Lockdown", check_lockdown())
    line("LSM", check_lsm())

    section(ICONS["hardening"], "Kernel Hardening")
    line("kptr_restrict", check_kptr_restrict())
    line("dmesg_restrict", check_dmesg_restrict())
    line("ptrace_scope", check_ptrace_scope())
    line("modules_disabled", check_modules_disabled())
    line("unprivileged_bpf", check_unprivileged_bpf())

    section(ICONS["network"], "Network")
    line("Firewall", status_firewall())
    line("Open Ports", check_open_ports())
    line("IPv6", check_ipv6())


if __name__ == "__main__":
    main()
