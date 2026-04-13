import argparse
import os
import select
import sys
import termios
import threading
import tty

from secfetch.core.engine import run_checks
from secfetch.data import port_db
from secfetch.ui.help import print_check_help, print_help
from secfetch.ui.improve import apply_fixes, print_improve
from secfetch.ui.output import print_results, print_results_live, print_results_short


def _wait_for_quit(stop_event: threading.Event) -> None:
    """Wait for 'q' key press on stdin without requiring Enter.

    Falls back to line-buffered input() when stdin is not a terminal.
    """
    if not sys.stdin.isatty():
        while not stop_event.is_set():
            try:
                key = input()
                if key.strip().lower() == "q":
                    stop_event.set()
            except (EOFError, ValueError):
                break
        return

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not stop_event.is_set():
            ready, _, _ = select.select([sys.stdin], [], [], 0.5)
            if ready:
                ch = sys.stdin.read(1)
                if ch and ch.lower() == "q":
                    stop_event.set()
    except (EOFError, OSError):
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def main():
    port_db.initialize()

    parser = argparse.ArgumentParser(prog="secfetch", add_help=False)
    parser.add_argument("command", nargs="?", default="scan", help=argparse.SUPPRESS)
    parser.add_argument("check", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--short", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--auto", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true", default=False, help=argparse.SUPPRESS)
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
        if args.interval < 1:
            print("  [!] --interval must be at least 1 second.")
            return
        stop_event = threading.Event()
        listener = threading.Thread(target=_wait_for_quit, args=(stop_event,), daemon=True)
        listener.start()

        try:
            while not stop_event.is_set():
                results = run_checks(fast=False)
                print_results_live(results, args.interval)
                stop_event.wait(timeout=args.interval)
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

    os.environ["SECFETCH_SHORT"] = "1" if args.short else "0"

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
