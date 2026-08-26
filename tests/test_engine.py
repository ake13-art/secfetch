"""Tests for the check engine."""

import importlib

import pytest

import secfesc.shared.registry as engine_module
from secfesc.shared.registry import get_checks, register, run_checks

# A valid (category, risk) pair for test-only checks.
_TEST_CATEGORY = "system"
_TEST_RISK = "low"


class TestRegistry:
    """Tests for check registration."""

    def test_register_and_get(self):
        initial_count = len(get_checks())
        check = {
            "name": "Test",
            "category": _TEST_CATEGORY,
            "risk": _TEST_RISK,
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

    def test_register_rejects_invalid_risk(self):
        """An invalid risk value must raise ValueError instead of being logged later."""
        with pytest.raises(ValueError, match="Invalid risk"):
            register({
                "name": "BadRisk",
                "category": _TEST_CATEGORY,
                "risk": "hgh",
                "run": lambda: {"status": "ok", "value": "x"},
            })


class TestRunChecks:
    """Tests for run_checks."""

    def _register_and_cleanup(self, check):
        """Helper to register a check and ensure cleanup."""
        register(check)

    def test_handles_broken_check(self):
        """A check that raises should not crash the engine and must not leak
        the exception text in the user-facing value."""

        def broken():
            raise RuntimeError("boom")

        check = {"name": "Broken", "category": _TEST_CATEGORY, "risk": _TEST_RISK, "run": broken}
        self._register_and_cleanup(check)
        try:
            results = run_checks(fast=False)
            broken_result = next(r for r in results if r["name"] == "Broken")
            assert broken_result["status"] == "info"
            # Generic message; no internal exception details exposed.
            assert broken_result["value"] == "check unavailable"
            assert "RuntimeError" not in broken_result["value"]
            assert "boom" not in broken_result["value"]
        finally:
            engine_module._checks.remove(check)

    def test_validates_invalid_result(self):
        """A check that returns invalid data should be caught."""

        def bad_return():
            return "not a dict"

        check = {"name": "BadReturn", "category": _TEST_CATEGORY, "risk": _TEST_RISK, "run": bad_return}
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

        check = {"name": "Incomplete", "category": _TEST_CATEGORY, "risk": _TEST_RISK, "run": incomplete}
        self._register_and_cleanup(check)
        try:
            results = run_checks(fast=False)
            result = next(r for r in results if r["name"] == "Incomplete")
            assert result["status"] == "info"
            assert result["value"] == "invalid check result"
        finally:
            engine_module._checks.remove(check)

    def test_validates_unknown_status(self):
        """A status outside the four-state vocabulary should be rejected."""

        def weird_status():
            return {"status": "blue", "value": "x"}

        check = {"name": "WeirdStatus", "category": _TEST_CATEGORY, "risk": _TEST_RISK, "run": weird_status}
        self._register_and_cleanup(check)
        try:
            results = run_checks(fast=False)
            result = next(r for r in results if r["name"] == "WeirdStatus")
            assert result["status"] == "info"
            assert result["value"] == "invalid check result"
        finally:
            engine_module._checks.remove(check)

    def test_discover_logs_import_errors(self, monkeypatch):
        """_discover_checks should log errors when a module fails to import."""
        from unittest.mock import MagicMock

        old_discovered = engine_module._discovered
        engine_module._discovered = False

        real_import = importlib.import_module
        call_count = [0]

        def failing_import(name):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ImportError("synthetic failure")
            return real_import(name)

        mock_imp = MagicMock()
        mock_imp.import_module = failing_import

        logged = []
        try:
            monkeypatch.setattr(engine_module, "importlib", mock_imp)
            monkeypatch.setattr(engine_module, "log_error", lambda m: logged.append(m))
            engine_module._discover_checks()
        finally:
            engine_module._discovered = old_discovered

        assert any("Failed to load" in m for m in logged)
        assert any("completed with" in m for m in logged)

    def test_preserves_order(self):
        """Results should maintain registration order."""

        def make_check(name):
            return {
                "name": name,
                "category": _TEST_CATEGORY,
                "risk": _TEST_RISK,
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
