import argparse
from secfetch.core.runner import run_checks
from secfetch.ui.output import print_results, print_results_short
from secfetch.ui.help import print_help, print_check_help


def main():
    parser = argparse.ArgumentParser(
        prog="secfetch",
        add_help=False,  # wir bauen -h selbst
    )

    parser.add_argument(
        "command",
        nargs="?",
        default="scan",
        help=argparse.SUPPRESS,  # commands erklären wir selbst unten
    )
    parser.add_argument(
        "check",
        nargs="?",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--short",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    # -h / --help → unsere eigene Hilfe
    if args.help:
        print_help()
        return

    if args.command == "help":
        if args.check:
            print_check_help(args.check)
        else:
            print_help()
        return

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
import argparse
from secfetch.core.runner import run_checks
from secfetch.ui.output import print_results, print_results_short
from secfetch.ui.help import print_help, print_check_help


def main():
    parser = argparse.ArgumentParser(
        prog="secfetch",
        add_help=False,  # wir bauen -h selbst
    )

    parser.add_argument(
        "command",
        nargs="?",
        default="scan",
        help=argparse.SUPPRESS,  # selfmade commands below
    )
    parser.add_argument(
        "check",
        nargs="?",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--short",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    # -h / --help → own created help
    if args.help:
        print_help()
        return

    if args.command == "help":
        if args.check:
            print_check_help(args.check)
        else:
            print_help()
        return

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

