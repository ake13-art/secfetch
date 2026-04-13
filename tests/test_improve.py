"""Tests for pure utility functions in ui/improve.py."""

from pathlib import Path
from unittest.mock import patch

from secfetch.ui.improve import (
    _extract_suspicious_services,
    _select_fixes,
    _write_sysctl_config,
)

# ─── _extract_suspicious_services ────────────────────────────────────────────


class TestExtractSuspiciousServices:
    def test_returns_matching_suspicious_services(self):
        results = [
            {"name": "Services", "status": "bad", "value": "5 running, suspicious: telnetd, ftpd"}
        ]
        found = _extract_suspicious_services(results)
        assert "telnetd" in found
        assert "ftpd" in found

    def test_returns_empty_if_service_not_in_suspicious_set(self):
        results = [{"name": "Services", "status": "ok", "value": "3 running, none flagged: sshd"}]
        found = _extract_suspicious_services(results)
        assert found == set()

    def test_returns_empty_if_no_colon_in_value(self):
        results = [{"name": "Services", "status": "bad", "value": "no colon here"}]
        found = _extract_suspicious_services(results)
        assert found == set()

    def test_returns_empty_if_services_not_in_results(self):
        results = [{"name": "ASLR", "status": "ok", "value": "Full"}]
        found = _extract_suspicious_services(results)
        assert found == set()

    def test_returns_empty_for_empty_results(self):
        assert _extract_suspicious_services([]) == set()

    def test_case_insensitive_name_match(self):
        results = [{"name": "SERVICES", "status": "bad", "value": "1 running, suspicious: telnetd"}]
        # Name comparison uses .lower(), so "SERVICES" matches "services"
        found = _extract_suspicious_services(results)
        assert "telnetd" in found

    def test_services_key_lowercase_matches(self):
        results = [{"name": "Services", "status": "bad", "value": "x: telnetd, rshd"}]
        found = _extract_suspicious_services(results)
        assert "telnetd" in found
        assert "rshd" in found

    def test_case_insensitive_service_value_match(self):
        """Service names in value with non-lowercase should still be matched."""
        results = [{"name": "Services", "status": "bad", "value": "1 running, suspicious: Telnetd"}]
        found = _extract_suspicious_services(results)
        assert "Telnetd" in found  # original case preserved for systemctl


# ─── _write_sysctl_config ─────────────────────────────────────────────────────


class TestWriteSysctlConfig:
    def test_creates_file_with_param(self, tmp_path, monkeypatch):
        target = tmp_path / "99-secfetch.conf"
        monkeypatch.setattr("secfetch.ui.improve.SYSCTL_FILE", str(target))
        result = _write_sysctl_config("kernel.kptr_restrict", "2")
        assert result is True
        assert "kernel.kptr_restrict = 2" in target.read_text()

    def test_appends_new_param_to_existing_file(self, tmp_path, monkeypatch):
        target = tmp_path / "99-secfetch.conf"
        target.write_text("kernel.dmesg_restrict = 1\n")
        monkeypatch.setattr("secfetch.ui.improve.SYSCTL_FILE", str(target))
        _write_sysctl_config("kernel.kptr_restrict", "2")
        content = target.read_text()
        assert "kernel.dmesg_restrict = 1" in content
        assert "kernel.kptr_restrict = 2" in content

    def test_updates_existing_param(self, tmp_path, monkeypatch):
        target = tmp_path / "99-secfetch.conf"
        target.write_text("kernel.kptr_restrict = 1\n")
        monkeypatch.setattr("secfetch.ui.improve.SYSCTL_FILE", str(target))
        _write_sysctl_config("kernel.kptr_restrict", "2")
        content = target.read_text()
        assert "kernel.kptr_restrict = 2" in content
        assert "kernel.kptr_restrict = 1" not in content

    def test_returns_false_on_permission_error(self, monkeypatch):
        def raise_permission(*args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr(Path, "write_text", raise_permission)
        result = _write_sysctl_config("kernel.kptr_restrict", "2")
        assert result is False


# ─── _select_fixes ────────────────────────────────────────────────────────────


class TestSelectFixes:
    def _make_fixable(self, selected=True, risky=False):
        return [
            {
                "name": "ASLR",
                "key": "aslr",
                "cmds": [["sudo", "sysctl", "-w", "kernel.randomize_va_space=2"]],
                "risky": risky,
                "selected": selected,
            }
        ]

    def test_quit_returns_none(self):
        with patch("builtins.input", return_value="q"):
            result = _select_fixes(self._make_fixable(), [])
        assert result is None

    def test_keyboard_interrupt_returns_none(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            result = _select_fixes(self._make_fixable(), [])
        assert result is None

    def test_eof_returns_none(self):
        with patch("builtins.input", side_effect=EOFError):
            result = _select_fixes(self._make_fixable(), [])
        assert result is None

    def test_empty_input_confirms_and_returns_selected(self):
        fixable = self._make_fixable(selected=True)
        with patch("builtins.input", return_value=""):
            result = _select_fixes(fixable, [])
        assert result is not None
        assert len(result) == 1
        assert result[0]["key"] == "aslr"

    def test_empty_input_with_nothing_selected_returns_empty_list(self):
        fixable = self._make_fixable(selected=False)
        with patch("builtins.input", return_value=""):
            result = _select_fixes(fixable, [])
        assert result == []

    def test_toggle_deselects_item(self):
        fixable = self._make_fixable(selected=True)
        with patch("builtins.input", side_effect=["1", ""]):
            result = _select_fixes(fixable, [])
        assert result == []

    def test_toggle_selects_item(self):
        fixable = self._make_fixable(selected=False)
        with patch("builtins.input", side_effect=["1", ""]):
            result = _select_fixes(fixable, [])
        assert len(result) == 1

    def test_all_selects_everything(self):
        fixable = self._make_fixable(selected=False)
        with patch("builtins.input", side_effect=["a", ""]):
            result = _select_fixes(fixable, [])
        assert len(result) == 1

    def test_none_deselects_everything(self):
        fixable = self._make_fixable(selected=True)
        with patch("builtins.input", side_effect=["n", ""]):
            result = _select_fixes(fixable, [])
        assert result == []

    def test_invalid_input_is_ignored(self):
        fixable = self._make_fixable(selected=True)
        with patch("builtins.input", side_effect=["xyz", ""]):
            result = _select_fixes(fixable, [])
        assert len(result) == 1

    def test_invalid_input_message_is_english(self, capsys):
        fixable = self._make_fixable(selected=True)
        with patch("builtins.input", side_effect=["xyz", ""]):
            _select_fixes(fixable, [])
        captured = capsys.readouterr()
        assert "Invalid input ignored" in captured.out
        assert "Ungültige" not in captured.out
