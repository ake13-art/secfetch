class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"

    WHITE = "\033[37m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"

    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


ICONS = {
    "system": "󰌢",
    "kernel": "󰒋",
    "hardening": "󰅐",
    "network": "󰖩",
}


def color(text, c):
    return f"{c}{text}{Color.RESET}"


def status_color(value):

    v = str(value).lower()

    good = ["enabled", "active", "full", "restricted", "integrity", "enforcing"]
    bad = ["disabled", "none", "off"]

    if any(x in v for x in good):
        return f"{Color.GREEN}{value}{Color.RESET}"

    if any(x in v for x in bad):
        return f"{Color.RED}{value}{Color.RESET}"

    return f"{Color.YELLOW}{value}{Color.RESET}"
