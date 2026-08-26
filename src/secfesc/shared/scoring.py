"""Shared scoring utilities."""
from __future__ import annotations

from secfesc.shared.logger import log_warning
from secfesc.shared.types import CategoryAccumulator, CheckResult

WEIGHTS: dict[str, int] = {"high": 30, "medium": 20, "low": 10, "info": 0}
_DEFAULT_WEIGHT = WEIGHTS["medium"]
_warned_risks: set[str] = set()


def _get_weight(risk: str) -> int:
    weight = WEIGHTS.get(risk)
    if weight is None:
        if risk not in _warned_risks:
            log_warning(
                f"Unknown risk level '{risk}', defaulting to weight {_DEFAULT_WEIGHT}"
            )
            _warned_risks.add(risk)
        return _DEFAULT_WEIGHT
    return weight


def calculate_score(
    results: list[CheckResult],
) -> tuple[int, dict[str, int], int]:
    """Calculate overall and per-category security scores.

    Scoring: ok = full points, warn = half points, bad = no points.
    Checks that returned ``status="info"`` (e.g. tool missing) are still
    counted in the denominator with zero points so that a system on which
    every check failed to run does not score 100/100.

    Returns ``(final, per_category, unavailable_count)`` where
    ``unavailable_count`` is the number of checks that returned ``info``.
    """
    total = 0
    earned = 0
    unavailable = 0
    categories: dict[str, CategoryAccumulator] = {}

    for result in results:
        status = result["status"]
        weight = _get_weight(result["risk"])
        total += weight

        if status == "ok":
            points = weight
        elif status == "warn":
            points = weight // 2
        else:
            # "bad" or "info" — info checks count toward the denominator
            # so a perfect score is not achievable by failing to run.
            points = 0
            if status == "info":
                unavailable += 1

        earned += points

        cat = categories.setdefault(result["category"], {"earned": 0, "total": 0})
        cat["total"] += weight
        cat["earned"] += points

    final = round((earned / total) * 100) if total else 0
    cat_scores = {
        k: round((v["earned"] / v["total"]) * 100) if v["total"] else 0
        for k, v in categories.items()
    }
    return final, cat_scores, unavailable
