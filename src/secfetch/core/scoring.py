from __future__ import annotations

WEIGHTS = {"high": 30, "medium": 20, "low": 10, "info": 0}


def calculate_score(results: list[dict]) -> tuple[int, dict]:
    # Calculate overall + per-category security score
    total, earned, categories = 0, 0, {}

    for result in results:
        weight = WEIGHTS.get(result["risk"], 0)
        total += weight
        # ok = full points, warn = half, bad/info = none
        points = weight if result["status"] == "ok" else weight // 2 if result["status"] == "warn" else 0
        earned += points

        cat = categories.setdefault(result["category"], {"earned": 0, "total": 0})
        cat["total"] += weight
        cat["earned"] += points

    final = int((earned / total) * 100) if total else 0
    cat_scores = {
        k: int((v["earned"] / v["total"]) * 100) if v["total"] else 0
        for k, v in categories.items()
    }
    return final, cat_scores
