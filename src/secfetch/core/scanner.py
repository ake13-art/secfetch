from secfetch.core.registry import get_checks


def run_checks():

    results = []

    for check in get_checks():
        try:
            raw = check["run"]()

            results.append(
                {
                    "name": check["name"],
                    "category": check["category"],
                    "risk": check["risk"],
                    "status": raw.get("status", "info"),
                    "value": raw.get("value", "Unknown"),
                }
            )

        except Exception as e:
            results.append(
                {
                    "name": check["name"],
                    "category": check["category"],
                    "risk": check["risk"],
                    "status": "info",
                    "value": f"Error: {e}",
                }
            )

    return results
