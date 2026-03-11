import argparse
import os
from secfetch.core.runner import run_checks
from secfetch.ui.output import print_results, print_results_short
from secfetch.ui.help import print_help, print_check_help
from secfetch.checks.network import port_db


def main():
    port_db.initialize()

    parser = argparse.ArgumentParser(prog="secfetch", add_help=False)
    parser.add_argument("command", nargs="?", default="scan", help=argparse.SUPPRESS)
    parser.add_argument("check", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--short", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "-h", "--help", action="store_true", default=False, help=argparse.SUPPRESS
    )

    args = parser.parse_args()

    if args.help:
        print_help()
        return

    if args.command == "help":
        if args.check:
            print_check_help(args.check)
        else:
            print_help()
        return

    # set before run_checks so ports.py can read it
    if args.short:
        os.environ["SECFETCH_SHORT"] = "1"

    if args.command == "fastscan":
        results = run_checks(fast=True)
    else:
        results = run_checks(fast=False)

    if args.short:
        print_results_short(results)
    else:
        print_results(results)


if __name__ == "__main__":
    main()
