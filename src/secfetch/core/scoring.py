def calculate_score(results: list[dict]) -> tuple[int, dict]:
    weights = {"high": 30, "medium": 20, "low": 10, "info": 0}
    total, score = 0, 0
    categories = {}

    for r in results:
        w = weights.get(r["risk"], 0)
        total += w

        # ok = full points, warn = half, bad/info = none
        if r["status"] == "ok":
            score += w
        elif r["status"] == "warn":
            score += w // 2

        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"score": 0, "total": 0}
        categories[cat]["total"] += w
        if r["status"] == "ok":
            categories[cat]["score"] += w
        elif r["status"] == "warn":
            categories[cat]["score"] += w // 2

    final = int((score / total) * 100) if total else 0
    cat_scores = {
        k: int((v["score"] / v["total"]) * 100) if v["total"] else 0
        for k, v in categories.items()
    }
    return final, cat_scores
