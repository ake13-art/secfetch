def calculate_score(results):

    weights = {
        "high": 30,
        "medium": 20,
        "low": 10,
        "info": 0,
    }

    total = 0
    score = 0
    categories = {}

    for r in results:
        risk = r["risk"]
        weight = weights.get(risk, 0)
        status = r["status"]

        total += weight

        # ok = volle Punkte, warn = halbe Punkte, bad/info = keine Punkte
        if status == "ok":
            score += weight
        elif status == "warn":
            score += weight // 2

        cat = r["category"]

        if cat not in categories:
            categories[cat] = {"score": 0, "total": 0}

        categories[cat]["total"] += weight

        if status == "ok":
            categories[cat]["score"] += weight
        elif status == "warn":
            categories[cat]["score"] += weight // 2

    final_score = int((score / total) * 100) if total else 0

    category_scores = {
        k: int((v["score"] / v["total"]) * 100) if v["total"] else 0
        for k, v in categories.items()
    }

    return final_score, category_scores
