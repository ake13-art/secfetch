"""Tests for the check engine."""

import secfetch.core.engine as engine_module
from secfetch.core.engine import get_checks, register, run_checks


class TestRegistry:
    """Tests for check registration."""

    def test_register_and_get(self):
        initial_count = len(get_checks())
        check = {
            "name": "Test",
            "category": "test",
            "risk": "low",
            "run": lambda: {"status": "ok", "value": "test"},
        }
        try:
            register(check)
            checks = get_checks()
            assert len(checks) == initial_count + 1
            assert checks[-1]["name"] == "Test"
        finally:
            all_checks = get_checks()
            if check in all_checks:
                engine_module._checks.remove(check)


class TestRunChecks:
    """Tests for run_checks."""

    def _register_and_cleanup(self, check):
        """Helper to register a check and ensure cleanup."""
        register(check)

    def test_handles_broken_check(self):
        """A check that raises should not crash the engine."""

        def broken():
            raise RuntimeError("boom")

        check = {"name": "Broken", "category": "test", "risk": "low", "run": broken}
        self._register_and_cleanup(check)
        try:
            results = run_checks(fast=False)
            broken_result = next(r for r in results if r["name"] == "Broken")
            assert broken_result["status"] == "info"
            assert "Error" in broken_result["value"]
        finally:
            engine_module._checks.remove(check)

    def test_validates_invalid_result(self):
        """A check that returns invalid data should be caught."""

        def bad_return():
            return "not a dict"

        check = {"name": "BadReturn", "category": "test", "risk": "low", "run": bad_return}
        self._register_and_cleanup(check)
        try:
            results = run_checks(fast=False)
            bad_result = next(r for r in results if r["name"] == "BadReturn")
            assert bad_result["status"] == "info"
            assert bad_result["value"] == "invalid check result"
        finally:
            engine_module._checks.remove(check)

    def test_validates_missing_keys(self):
        """A check that returns a dict without required keys should be caught."""

        def incomplete():
            return {"status": "ok"}

        check = {"name": "Incomplete", "category": "test", "risk": "low", "run": incomplete}
        self._register_and_cleanup(check)
        try:
            results = run_checks(fast=False)
            result = next(r for r in results if r["name"] == "Incomplete")
            assert result["status"] == "info"
            assert result["value"] == "invalid check result"
        finally:
            engine_module._checks.remove(check)

    def test_preserves_order(self):
        """Results should maintain registration order."""

        def make_check(name):
            return {
                "name": name,
                "category": "test",
                "risk": "low",
                "run": lambda n=name: {"status": "ok", "value": n},
            }

        checks = [make_check(f"Order{i}") for i in range(5)]
        for c in checks:
            self._register_and_cleanup(c)
        try:
            results = run_checks(fast=False)
            order_results = [r for r in results if r["name"].startswith("Order")]
            assert len(order_results) == 5
            for i, r in enumerate(order_results):
                assert r["name"] == f"Order{i}"
        finally:
            for c in checks:
                if c in engine_module._checks:
                    engine_module._checks.remove(c)
