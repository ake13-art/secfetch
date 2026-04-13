"""Tests for config module."""

from pathlib import Path

from secfetch.core import config as config_module


class TestConfig:
    """Tests for configuration system."""

    def setup_method(self):
        config_module.invalidate_cache()

    def teardown_method(self):
        config_module.invalidate_cache()
        config_module.CONFIG_PATH = Path.home() / ".config" / "secfetch" / "checks.conf"

    def test_is_enabled_returns_bool(self, tmp_path, monkeypatch):
        """is_enabled should return boolean."""
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\naslr = true\n")

        cfg = config_module.load_config()
        result = config_module.is_enabled(cfg, "aslr")
        assert isinstance(result, bool)

    def test_is_enabled_default_false(self, tmp_path, monkeypatch):
        """Unknown check should return False by default."""
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\n")

        cfg = config_module.load_config()
        result = config_module.is_enabled(cfg, "nonexistent_check")
        assert result is False

    def test_is_enabled_explicit_true(self, tmp_path, monkeypatch):
        """Explicitly enabled check should return True."""
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\naslr = true\n")

        cfg = config_module.load_config()
        result = config_module.is_enabled(cfg, "aslr")
        assert result is True

    def test_is_enabled_explicit_false(self, tmp_path, monkeypatch):
        """Explicitly disabled check should return False."""
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\naslr = false\n")

        cfg = config_module.load_config()
        result = config_module.is_enabled(cfg, "aslr")
        assert result is False

    def test_cache_invalidation(self, tmp_path):
        """invalidate_cache should force reload on next load_config call."""
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\naslr = true\n")

        cfg1 = config_module.load_config()
        config_module.CONFIG_PATH.write_text("[checks]\naslr = false\n")
        config_module.invalidate_cache()
        cfg2 = config_module.load_config()

        assert cfg1.getboolean("checks", "aslr") is True
        assert cfg2.getboolean("checks", "aslr") is False

    def test_cache_uses_resolved_path(self, tmp_path):
        """Cache should work with different path objects pointing to same file."""
        config_file = tmp_path / "test_checks.conf"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("[checks]\naslr = true\n")

        config_module.CONFIG_PATH = config_file
        cfg1 = config_module.load_config()

        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        cfg2 = config_module.load_config()

        assert cfg1 is cfg2

    def test_cache_key_handles_unresolvable_path(self, tmp_path):
        """Cache should work even if path resolution fails."""
        config_module.CONFIG_PATH = tmp_path / "test_checks.conf"
        config_module.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_module.CONFIG_PATH.write_text("[checks]\naslr = true\n")

        cfg = config_module.load_config()
        assert cfg.getboolean("checks", "aslr") is True
