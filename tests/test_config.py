"""
Tests for config module
"""
import pytest
from secfetch.core.config import load_config, is_enabled


class TestConfig:
    """Tests for configuration system."""

    def test_is_enabled_returns_bool(self, tmp_path, monkeypatch):
        """is_enabled should return boolean."""
        from secfetch.core import config as config_module
        
        # Create temp config
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\naslr = true\n")
        
        cfg = config_module.load_config()
        result = config_module.is_enabled(cfg, "aslr")
        assert isinstance(result, bool)

    def test_is_enabled_default_false(self, tmp_path, monkeypatch):
        """Unknown check should return False by default."""
        from secfetch.core import config as config_module
        
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\n")
        
        cfg = config_module.load_config()
        result = config_module.is_enabled(cfg, "nonexistent_check")
        assert result is False

    def test_is_enabled_explicit_true(self, tmp_path, monkeypatch):
        """Explicitly enabled check should return True."""
        from secfetch.core import config as config_module
        
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\naslr = true\n")
        
        cfg = config_module.load_config()
        result = config_module.is_enabled(cfg, "aslr")
        assert result is True

    def test_is_enabled_explicit_false(self, tmp_path, monkeypatch):
        """Explicitly disabled check should return False."""
        from secfetch.core import config as config_module
        
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\naslr = false\n")
        
        cfg = config_module.load_config()
        result = config_module.is_enabled(cfg, "aslr")
        assert result is False
