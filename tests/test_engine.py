"""Tests for the check engine."""

from secfetch.core.engine import _checks, get_checks, register, run_checks


class TestRegistry:
    """Tests for check registration."""

    def test_register_and_get(self):
        initial_count = len(_checks)
        check = {"name": "Test", "category": "test", "risk": "low", "run": lambda: {"status": "ok", "value": "test"}}
        register(check)
        checks = get_checks()
        assert len(checks) == initial_count + 1
        assert checks[-1]["name"] == "Test"
        # Clean up
        _checks.pop()


class TestRunChecks:
    """Tests for run_checks."""

    def test_handles_broken_check(self):
        """A check that raises should not crash the engine."""
        def broken():
            raise RuntimeError("boom")

        _checks.append({"name": "Broken", "category": "test", "risk": "low", "run": broken})
        try:
            results = run_checks(fast=False)
            broken_result = next(r for r in results if r["name"] == "Broken")
            assert broken_result["status"] == "info"
            assert "Error" in broken_result["value"]
        finally:
            _checks.pop()

    def test_validates_invalid_result(self):
        """A check that returns invalid data should be caught."""
        def bad_return():
            return "not a dict"

        _checks.append({"name": "BadReturn", "category": "test", "risk": "low", "run": bad_return})
        try:
            results = run_checks(fast=False)
            bad_result = next(r for r in results if r["name"] == "BadReturn")
            assert bad_result["status"] == "info"
            assert bad_result["value"] == "invalid check result"
        finally:
            _checks.pop()

    def test_validates_missing_keys(self):
        """A check that returns a dict without required keys should be caught."""
        def incomplete():
            return {"status": "ok"}

        _checks.append({"name": "Incomplete", "category": "test", "risk": "low", "run": incomplete})
        try:
            results = run_checks(fast=False)
            result = next(r for r in results if r["name"] == "Incomplete")
            assert result["status"] == "info"
            assert result["value"] == "invalid check result"
        finally:
            _checks.pop()
