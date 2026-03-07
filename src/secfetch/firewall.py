import subprocess


def nft_ruleset():
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"], capture_output=True, text=True
        )

        if result.returncode != 0:
            return None

        return result.stdout

    except FileNotFoundError:
        return None


def status_firewall():
    ruleset = nft_ruleset()

    if not ruleset:
        return "Inactive"

    if "hook input" in ruleset:
        return "Active"

    return "Inactive"

