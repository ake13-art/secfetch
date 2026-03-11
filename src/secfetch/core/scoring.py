WEIGHTS = {"high": 30, "medium": 20, "low": 10, "info": 0}


def calculate_score(results: list[dict]) -> tuple[int, dict]:
    # Calculate overall + per-category security score
    total, earned, cats = 0, 0, {}

    for r in results:
        w = WEIGHTS.get(r["risk"], 0)
        total += w
        # ok = full points, warn = half, bad/info = none
        pts = w if r["status"] == "ok" else w // 2 if r["status"] == "warn" else 0
        earned += pts

        cat = cats.setdefault(r["category"], {"earned": 0, "total": 0})
        cat["total"] += w
        cat["earned"] += pts

    final = int((earned / total) * 100) if total else 0
    cat_scores = {
        k: int((v["earned"] / v["total"]) * 100) if v["total"] else 0
        for k, v in cats.items()
    }
    return final, cat_scores
