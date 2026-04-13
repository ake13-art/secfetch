"""Tests for the help system (ui/help.py)."""
from unittest.mock import patch

from secfetch.ui.help import CHECK_DESCRIPTIONS, print_check_help, print_help


class TestCheckDescriptions:
    def test_all_entries_have_required_keys(self):
        required = {"title", "category", "risk", "description", "good", "bad", "fix"}
        for key, info in CHECK_DESCRIPTIONS.items():
            missing = required - set(info.keys())
            assert not missing, f"Check '{key}' missing keys: {missing}"

    def test_known_checks_present(self):
        for key in ("aslr", "firewall_rules", "open_ports", "lsm", "services"):
            assert key in CHECK_DESCRIPTIONS, f"Missing check: {key}"

    def test_risk_values_are_valid(self):
        valid = {"Low", "Medium", "High", "Info"}
        for key, info in CHECK_DESCRIPTIONS.items():
            assert info["risk"] in valid, f"Invalid risk '{info['risk']}' for check '{key}'"


class TestPrintHelp:
    def test_prints_usage_section(self, capsys):
        print_help()
        out = capsys.readouterr().out
        assert "secfetch" in out
        assert "improve" in out

    def test_prints_all_check_keys(self, capsys):
        print_help()
        out = capsys.readouterr().out
        for key in CHECK_DESCRIPTIONS:
            assert key in out, f"Check key '{key}' not found in help output"


class TestPrintCheckHelp:
    def test_known_check_prints_details(self, capsys):
        print_check_help("aslr")
        out = capsys.readouterr().out
        assert "ASLR" in out
        assert "Kernel Security" in out

    def test_unknown_check_prints_error(self, capsys):
        print_check_help("nonexistent_check_xyz")
        out = capsys.readouterr().out
        assert "Unknown check" in out
        assert "secfetch help" in out

    def test_unknown_check_logs_warning(self):
        with patch("secfetch.ui.help.log_warning") as mock_warn:
            print_check_help("nonexistent_check_xyz")
            mock_warn.assert_called_once()
            assert "nonexistent_check_xyz" in mock_warn.call_args[0][0]

    def test_name_normalization(self, capsys):
        """'Open Ports' should resolve to key 'open_ports'."""
        print_check_help("Open Ports")
        out = capsys.readouterr().out
        assert "Open Ports" in out
        assert "Unknown check" not in out
