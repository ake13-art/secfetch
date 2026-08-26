"""Tests for key consistency across config, help descriptions, and auto-fixes."""
import configparser
import importlib
import pkgutil
import sys

import pytest

import secfesc.checks
from secfesc.secfetch.ui.help import CHECK_DESCRIPTIONS
from secfesc.secfetch.ui.improve import AUTO_FIXES
from secfesc.shared.config import DEFAULT_CONFIG
from secfesc.shared.registry import VALID_CATEGORIES


def _get_check_keys():
    """Get all check keys by importing all check modules fresh and reading _checks."""
    from secfesc.shared.registry import _checks

    # Clear the registry so previously-registered test artifacts don't leak
    # in, then reload every check module. Reload re-runs the
    # @security_check decorators that re-add the check to the registry.
    _checks.clear()

    for mod in pkgutil.walk_packages(
        secfesc.checks.__path__,
        secfesc.checks.__name__ + ".",
    ):
        try:
            if mod.name in sys.modules:
                importlib.reload(sys.modules[mod.name])
            else:
                importlib.import_module(mod.name)
        except (ImportError, ModuleNotFoundError, SyntaxError) as e:
            pytest.fail(f"Failed to import check module {mod.name}: {e}")

    return {
        c["name"].lower().replace(" ", "_")
        for c in _checks
        if c["category"] in VALID_CATEGORIES
    }


class TestKeyConsistency:
    """Ensure check name derivation matches keys in config, help, and auto-fixes."""

    def test_all_config_keys_match_check_names(self):
        """Every key in DEFAULT_CONFIG should correspond to an actual check."""
        check_keys = _get_check_keys()
        config = configparser.ConfigParser()
        config.read_string(DEFAULT_CONFIG.strip())

        for config_key in config.options("checks"):
            assert config_key in check_keys, (
                f"Config key '{config_key}' does not match any check. "
                f"Available: {sorted(check_keys)}"
            )

    def test_all_help_keys_match_check_names(self):
        """Every key in CHECK_DESCRIPTIONS should correspond to an actual check."""
        check_keys = _get_check_keys()

        for help_key in CHECK_DESCRIPTIONS:
            assert help_key in check_keys, (
                f"Help key '{help_key}' does not match any check. "
                f"Available: {sorted(check_keys)}"
            )

    def test_all_auto_fix_keys_match_check_names(self):
        """Every key in AUTO_FIXES should correspond to an actual check."""
        check_keys = _get_check_keys()

        for fix_key in AUTO_FIXES:
            assert fix_key in check_keys, (
                f"AUTO_FIXES key '{fix_key}' does not match any check. "
                f"Available: {sorted(check_keys)}"
            )

    def test_all_checks_have_help_entry(self):
        """Every registered check should have a help description."""
        check_keys = _get_check_keys()
        for key in check_keys:
            assert key in CHECK_DESCRIPTIONS, (
                f"Check key '{key}' has no help entry in CHECK_DESCRIPTIONS"
            )
