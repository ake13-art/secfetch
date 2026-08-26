"""
Tests for scoring module
"""
from secfesc.shared.scoring import WEIGHTS, calculate_score


class TestCalculateScore:
    """Tests for score calculation."""

    def test_all_ok(self, all_ok_results):
        """All checks passing should return 100."""
        score, cat_scores, unavailable = calculate_score(all_ok_results)
        assert score == 100
        assert unavailable == 0

    def test_all_bad(self, all_bad_results):
        """All checks failing should return 0."""
        score, cat_scores, unavailable = calculate_score(all_bad_results)
        assert score == 0
        assert unavailable == 0

    def test_mixed_results(self, sample_results):
        """Mixed results should return appropriate score."""
        score, cat_scores, unavailable = calculate_score(sample_results)
        assert 0 <= score <= 100

    def test_empty_results(self):
        """Empty results should return 0."""
        score, cat_scores, unavailable = calculate_score([])
        assert score == 0
        assert cat_scores == {}
        assert unavailable == 0

    def test_info_counts_in_denominator(self):
        """Checks returning info must drag the score below 100, not be skipped."""
        results = [
            {"name": "T1", "category": "c", "risk": "high", "status": "ok", "value": "v"},
            {"name": "T2", "category": "c", "risk": "high", "status": "info", "value": "v"},
        ]
        score, _, unavailable = calculate_score(results)
        assert unavailable == 1
        assert score == 50  # 30 earned out of 60 total

    def test_all_info_scores_zero(self):
        """If every check returned info the score must be 0, not 100."""
        results = [
            {"name": "T1", "category": "c", "risk": "high", "status": "info", "value": "v"},
            {"name": "T2", "category": "c", "risk": "high", "status": "info", "value": "v"},
        ]
        score, _, _ = calculate_score(results)
        assert score == 0

    def test_weights_exist(self):
        """WEIGHTS should have all required risk levels."""
        assert "high" in WEIGHTS
        assert "medium" in WEIGHTS
        assert "low" in WEIGHTS
        assert "info" in WEIGHTS

    def test_high_risk_weight(self):
        """High risk should have highest weight."""
        assert WEIGHTS["high"] > WEIGHTS["medium"]
        assert WEIGHTS["high"] > WEIGHTS["low"]
        assert WEIGHTS["high"] > WEIGHTS["info"]

    def test_category_scores(self, sample_results):
        """Category scores should be calculated correctly."""
        score, cat_scores, _ = calculate_score(sample_results)
        assert isinstance(cat_scores, dict)
        for cat_score in cat_scores.values():
            assert 0 <= cat_score <= 100
