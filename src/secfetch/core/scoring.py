from __future__ import annotations

from secfetch.core.types import CategoryAccumulator, CheckResult

WEIGHTS: dict[str, int] = {"high": 30, "medium": 20, "low": 10, "info": 0}


def calculate_score(results: list[CheckResult]) -> tuple[int, dict[str, int]]:
    """Calculate overall and per-category security scores.

    Scoring: ok = full points, warn = half points, bad/info = no points.
    """
    total = 0
    earned = 0
    categories: dict[str, CategoryAccumulator] = {}

    for result in results:
        weight = WEIGHTS.get(result["risk"], 0)
        total += weight
        if result["status"] == "ok":
            points = weight
        elif result["status"] == "warn":
            points = weight // 2
        else:
            points = 0
        earned += points

        cat = categories.setdefault(result["category"], {"earned": 0, "total": 0})
        cat["total"] += weight
        cat["earned"] += points

    final = int((earned / total) * 100) if total else 0
    cat_scores = {
        k: int((v["earned"] / v["total"]) * 100) if v["total"] else 0 for k, v in categories.items()
    }
    return final, cat_scores
