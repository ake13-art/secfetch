import sys
from secfetch.core.loader import load_checks
from secfetch.core.scanner import run_checks
from secfetch.ui.output import print_results, print_short
from secfetch.ui.help import print_help, print_check_help


def main():
    args = sys.argv[1:]

    if "help" in args:
        idx = args.index("help")
        # secfetch help <check>
        if idx + 1 < len(args):
            check_name = args[idx + 1]
            print_check_help(check_name)
        else:
            print_help()
        return

    load_checks()
    results = run_checks()

    if "--short" in args:
        print_short(results)
    else:
        print_results(results)
