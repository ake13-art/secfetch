from secfetch.core.config import load_config, is_enabled
from secfetch.core.loader import load_checks
from secfetch.core.registry import get_checks


def run_checks(fast: bool = False) -> list[dict]:
    config = load_config()
    load_checks()

    results = []
    for check in get_checks():
        # In fastscan mode, skip checks disabled in config
        key = check["name"].lower().replace(" ", "_")
        if fast and not is_enabled(config, key):
            continue
        result = check["run"]()
        result.update(
            name=check["name"], category=check["category"], risk=check["risk"]
        )
        results.append(result)
    return results
