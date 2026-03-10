from secfetch.core.config import load_config, is_enabled
from secfetch.core.loader import load_checks
from secfetch.core.registry import get_checks


def run_checks(fast: bool = False) -> list[dict]:
    config = load_config()
    load_checks()  # import all check modules so they register themselves

    results = []
    for check in get_checks():
        # skip disabled checks in fastscan mode
        if fast and not is_enabled(config, check["name"].lower().replace(" ", "_")):
            continue
        result = check["run"]()
        result["name"] = check["name"]
        result["category"] = check["category"]
        result["risk"] = check["risk"]
        results.append(result)

    return results
