"""Tests for key consistency across config, help descriptions, and auto-fixes."""
import configparser
import importlib
import pkgutil

import secfetch.checks
from secfetch.core.config import DEFAULT_CONFIG
from secfetch.ui.help import CHECK_DESCRIPTIONS
from secfetch.ui.improve import AUTO_FIXES


def _get_check_keys():
    """Get all check keys by importing all check modules fresh and reading _checks."""
    from secfetch.core.engine import _checks

    # Ensure all check modules are imported (decorators register checks on import)
    for mod in pkgutil.walk_packages(
        secfetch.checks.__path__,
        secfetch.checks.__name__ + ".",
    ):
        try:
            importlib.import_module(mod.name)
        except Exception:
            pass

    # Collect keys, filtering out non-real categories (from test artifacts)
    real_categories = {
        "system", "kernel_security", "kernel_hardening", "network", "filesystem",
    }
    return {
        c["name"].lower().replace(" ", "_")
        for c in _checks
        if c["category"] in real_categories
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
