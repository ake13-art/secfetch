import argparse
import threading
import time

from secfetch.core.engine import run_checks
from secfetch.data import port_db
from secfetch.ui.help import print_check_help, print_help
from secfetch.ui.improve import apply_fixes, print_improve
from secfetch.ui.output import print_results, print_results_live, print_results_short


def main():
    port_db.initialize()

    parser = argparse.ArgumentParser(prog="secfetch", add_help=False)
    parser.add_argument("command", nargs="?", default="scan", help=argparse.SUPPRESS)
    parser.add_argument("check", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--short", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--auto", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "-h", "--help", action="store_true", default=False, help=argparse.SUPPRESS
    )
    parser.add_argument("--interval", type=int, default=5, help=argparse.SUPPRESS)

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

    if args.command == "live":
        stop_event = threading.Event()

        def wait_for_quit():
            while not stop_event.is_set():
                try:
                    key = input()
                    if key.strip().lower() == "q":
                        stop_event.set()
                except EOFError:
                    break

        listener = threading.Thread(target=wait_for_quit, daemon=True)
        listener.start()

        try:
            while not stop_event.is_set():
                results = run_checks(fast=False)
                print_results_live(results, args.interval)
                for _ in range(args.interval * 10):
                    if stop_event.is_set():
                        break
                    time.sleep(0.1)
        except KeyboardInterrupt:
            pass

        print("\n  Live monitoring stopped.")
        return

    if args.command == "improve":
        results = run_checks(fast=False)
        if args.auto:
            apply_fixes(results)
        else:
            print_improve(results)
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
