"""Tests for pure utility functions in ui/improve.py."""

import subprocess
from unittest.mock import patch

from secfesc.secfetch.ui.improve import (
    _build_fixable_list,
    _check_firewall_available,
    _extract_suspicious_services,
    _run_command,
    _select_fixes,
    _write_sysctl_config,
    apply_fixes,
    print_improve,
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
        target = tmp_path / "99-secfesc.conf"
        monkeypatch.setattr("secfesc.secfetch.ui.improve.SYSCTL_FILE", str(target))
        result = _write_sysctl_config("kernel.kptr_restrict", "2")
        assert result is True
        assert "kernel.kptr_restrict = 2" in target.read_text()

    def test_appends_new_param_to_existing_file(self, tmp_path, monkeypatch):
        target = tmp_path / "99-secfesc.conf"
        target.write_text("kernel.dmesg_restrict = 1\n")
        monkeypatch.setattr("secfesc.secfetch.ui.improve.SYSCTL_FILE", str(target))
        _write_sysctl_config("kernel.kptr_restrict", "2")
        content = target.read_text()
        assert "kernel.dmesg_restrict = 1" in content
        assert "kernel.kptr_restrict = 2" in content

    def test_updates_existing_param(self, tmp_path, monkeypatch):
        target = tmp_path / "99-secfesc.conf"
        target.write_text("kernel.kptr_restrict = 1\n")
        monkeypatch.setattr("secfesc.secfetch.ui.improve.SYSCTL_FILE", str(target))
        _write_sysctl_config("kernel.kptr_restrict", "2")
        content = target.read_text()
        assert "kernel.kptr_restrict = 2" in content
        assert "kernel.kptr_restrict = 1" not in content

    def test_strips_trailing_blank_lines(self, tmp_path, monkeypatch):
        target = tmp_path / "99-secfesc.conf"
        target.write_text("kernel.kptr_restrict = 1\n\n\n")
        monkeypatch.setattr("secfesc.secfetch.ui.improve.SYSCTL_FILE", str(target))
        _write_sysctl_config("kernel.kptr_restrict", "2")
        content = target.read_text()
        assert not content.endswith("\n\n")

    def test_returns_false_on_permission_error(self, monkeypatch):
        def raise_permission(*args, **kwargs):
            raise PermissionError("denied")

        import os as _os
        monkeypatch.setattr(_os, "open", raise_permission)
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

    def test_services_fix_shows_service_names(self, capsys):
        fixable = [
            {
                "name": "Suspicious Services",
                "key": "services",
                "cmds": [],
                "risky": False,
                "selected": True,
                "services": ["telnetd"],
            }
        ]
        with patch("builtins.input", return_value="q"):
            _select_fixes(fixable, [])
        assert "telnetd" in capsys.readouterr().out

    def test_manual_only_shown_in_display(self, capsys):
        manual = [{"name": "Secure Boot", "status": "bad", "value": "Disabled"}]
        with patch("builtins.input", return_value="q"):
            _select_fixes(self._make_fixable(), manual)
        assert "Secure Boot" in capsys.readouterr().out

    def test_risky_toggle_shows_warning(self, capsys):
        fixable = [
            {
                "name": "Modules Disabled",
                "key": "modules_disabled",
                "cmds": [["sudo", "sysctl", "-w", "kernel.modules_disabled=1"]],
                "risky": True,
                "selected": False,
                "services": [],
            }
        ]
        with patch("builtins.input", side_effect=["1", "q"]):
            _select_fixes(fixable, [])
        out = capsys.readouterr().out
        assert "Warning" in out or "Irreversible" in out


# ─── _build_fixable_list ──────────────────────────────────────────────────────


class TestBuildFixableList:
    def _r(self, name, status="bad"):
        return {"name": name, "status": status, "value": "bad"}

    def test_auto_fixable_check_in_fixable(self):
        fixable, manual = _build_fixable_list([self._r("ASLR")], True, set())
        assert any(f["key"] == "aslr" for f in fixable)
        assert not any(r["name"] == "ASLR" for r in manual)

    def test_manual_only_check_not_in_fixable(self):
        fixable, manual = _build_fixable_list([self._r("Secure Boot")], True, set())
        assert len(fixable) == 0
        assert any(r["name"] == "Secure Boot" for r in manual)

    def test_firewall_not_available_goes_to_manual(self):
        fixable, manual = _build_fixable_list([self._r("Firewall Rules")], False, set())
        assert not any(f["key"] == "firewall_rules" for f in fixable)
        assert any(r["name"] == "Firewall Rules" for r in manual)

    def test_firewall_available_is_auto_fixable(self):
        fixable, _ = _build_fixable_list([self._r("Firewall Rules")], True, set())
        assert any(f["key"] == "firewall_rules" for f in fixable)

    def test_suspicious_services_added_to_fixable(self):
        fixable, _ = _build_fixable_list([], True, {"telnetd"})
        svc = next((f for f in fixable if f["key"] == "services"), None)
        assert svc is not None
        assert "telnetd" in svc["services"]

    def test_risky_fix_is_not_selected_by_default(self):
        fixable, _ = _build_fixable_list([self._r("Modules Disabled")], True, set())
        risky = next((f for f in fixable if f["key"] == "modules_disabled"), None)
        assert risky is not None
        assert risky["selected"] is False
        assert risky["risky"] is True

    def test_non_risky_fix_is_not_selected_by_default(self):
        """Safety: no fix should be pre-selected. The user must opt in for
        every item via the toggle."""
        fixable, _ = _build_fixable_list([self._r("ASLR")], True, set())
        item = next(f for f in fixable if f["key"] == "aslr")
        assert item["selected"] is False
        assert item["risky"] is False

    def test_suspicious_services_not_selected_by_default(self):
        fixable, _ = _build_fixable_list([], True, {"telnetd"})
        svc = next(f for f in fixable if f["key"] == "services")
        assert svc["selected"] is False


# ─── _run_command ─────────────────────────────────────────────────────────────


class TestRunCommand:
    def test_success_returns_true(self, capsys):
        assert _run_command(["true"]) is True
        assert "Applied" in capsys.readouterr().out

    def test_nonzero_returns_false(self, capsys):
        assert _run_command(["false"]) is False
        assert "Failed" in capsys.readouterr().out

    def test_command_not_found_returns_false(self, capsys):
        assert _run_command(["no_such_cmd_xyz_secfesc"]) is False
        assert "Failed" in capsys.readouterr().out

    def test_ufw_not_found_has_install_hint(self, capsys):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = _run_command(["ufw", "enable"])
        assert result is False
        assert "ufw not installed" in capsys.readouterr().out

    def test_timeout_returns_false(self, capsys):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["cmd"], 30)):
            result = _run_command(["some", "cmd"])
        assert result is False
        assert "timeout" in capsys.readouterr().out.lower()

    def test_generic_exception_returns_false(self, capsys):
        with patch("subprocess.run", side_effect=RuntimeError("boom")):
            result = _run_command(["cmd"])
        assert result is False
        assert "Failed" in capsys.readouterr().out


# ─── _check_firewall_available ────────────────────────────────────────────────


class TestCheckFirewallAvailable:
    def test_returns_true_when_ufw_present(self, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve.shutil.which",
                            lambda name: "/usr/bin/ufw" if name == "ufw" else None)
        assert _check_firewall_available() is True

    def test_returns_true_when_iptables_present(self, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve.shutil.which",
                            lambda name: "/sbin/iptables" if name == "iptables" else None)
        assert _check_firewall_available() is True

    def test_returns_false_when_nothing_present(self, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve.shutil.which", lambda name: None)
        assert _check_firewall_available() is False


# ─── print_improve ────────────────────────────────────────────────────────────


class TestPrintImprove:
    def test_all_passed_nothing_to_improve(self, capsys):
        print_improve([{"name": "ASLR", "status": "ok", "value": "Full"}])
        assert "nothing to improve" in capsys.readouterr().out

    def test_shows_failed_check_name(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        print_improve([{"name": "ASLR", "status": "bad", "value": "None"}])
        assert "ASLR" in capsys.readouterr().out

    def test_warn_status_shown(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        print_improve([{"name": "TCP SYN Cookies", "status": "warn", "value": "Disabled"}])
        out = capsys.readouterr().out
        assert "TCP SYN Cookies" in out

    def test_auto_fixable_tag_shown(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        print_improve([{"name": "ASLR", "status": "bad", "value": "None"}])
        assert "auto-fixable" in capsys.readouterr().out

    def test_firewall_not_available_shows_ufw_hint(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: False)
        print_improve([{"name": "Firewall Rules", "status": "bad", "value": "None"}])
        assert "ufw" in capsys.readouterr().out.lower()

    def test_fixable_count_message_shown(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        print_improve([{"name": "ASLR", "status": "bad", "value": "None"}])
        assert "auto-fix" in capsys.readouterr().out.lower()


# ─── apply_fixes ──────────────────────────────────────────────────────────────


class TestApplyFixes:
    def test_all_passed_nothing_to_fix(self, capsys):
        apply_fixes([{"name": "ASLR", "status": "ok", "value": "Full"}])
        assert "nothing to fix" in capsys.readouterr().out

    def test_failed_but_not_fixable_says_so(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        apply_fixes([{"name": "Secure Boot", "status": "bad", "value": "Disabled"}])
        assert "none are auto-fixable" in capsys.readouterr().out

    def test_select_returns_none_returns_silently(self, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        monkeypatch.setattr("secfesc.secfetch.ui.improve._select_fixes", lambda *a: None)
        with patch("builtins.input", return_value="yes apply"):
            apply_fixes([{"name": "ASLR", "status": "bad", "value": "None"}])

    def test_empty_selection_prints_nothing_selected(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        monkeypatch.setattr("secfesc.secfetch.ui.improve._select_fixes", lambda *a: [])
        with patch("builtins.input", return_value="yes apply"):
            apply_fixes([{"name": "ASLR", "status": "bad", "value": "None"}])
        assert "Nothing selected" in capsys.readouterr().out

    def test_user_refuses_at_confirm(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        selected = [{"name": "ASLR", "key": "aslr",
                     "cmds": [["sudo", "sysctl", "-w", "x=2"]],
                     "risky": False, "selected": True, "services": []}]
        monkeypatch.setattr("secfesc.secfetch.ui.improve._select_fixes", lambda *a: selected)
        with patch("builtins.input", return_value="n"):
            apply_fixes([{"name": "ASLR", "status": "bad", "value": "None"}])
        assert "Aborted" in capsys.readouterr().out

    def test_user_refuses_at_root_gate(self, capsys, monkeypatch):
        """Anything other than 'yes apply' at the initial root-sudo gate
        must abort before the selection wizard even runs."""
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        with patch("builtins.input", return_value="y"):
            apply_fixes([{"name": "ASLR", "status": "bad", "value": "None"}])
        out = capsys.readouterr().out
        assert "Aborted" in out

    def test_applies_commands_on_confirm(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        selected = [{"name": "ASLR", "key": "aslr",
                     "cmds": [["echo", "test"]],
                     "risky": False, "selected": True, "services": []}]
        monkeypatch.setattr("secfesc.secfetch.ui.improve._select_fixes", lambda *a: selected)
        monkeypatch.setattr("secfesc.secfetch.ui.improve._run_command", lambda cmd: True)
        # First input is the root-sudo gate, then the "Proceed? [y/N]".
        with patch("builtins.input", side_effect=["yes apply", "y"]):
            apply_fixes([{"name": "ASLR", "status": "bad", "value": "None"}])

    def test_applies_services_fix(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        selected = [{"name": "Suspicious Services", "key": "services",
                     "cmds": [], "risky": False, "selected": True,
                     "services": ["telnetd"]}]
        monkeypatch.setattr("secfesc.secfetch.ui.improve._select_fixes", lambda *a: selected)
        ran = []
        monkeypatch.setattr("secfesc.secfetch.ui.improve._run_command", lambda cmd: ran.append(cmd) or True)
        with patch("builtins.input", side_effect=["yes apply", "y"]):
            apply_fixes([{"name": "Services", "status": "bad", "value": "x: telnetd"}])
        assert any("telnetd" in " ".join(cmd) for cmd in ran)

    def test_sysctl_persistence_applied(self, capsys, monkeypatch, tmp_path):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        selected = [{"name": "ASLR", "key": "aslr",
                     "cmds": [["sudo", "sysctl", "-w", "kernel.randomize_va_space=2"]],
                     "risky": False, "selected": True, "services": []}]
        monkeypatch.setattr("secfesc.secfetch.ui.improve._select_fixes", lambda *a: selected)
        monkeypatch.setattr("secfesc.secfetch.ui.improve._run_command", lambda cmd: True)
        conf = tmp_path / "99-secfesc.conf"
        monkeypatch.setattr("secfesc.secfetch.ui.improve.SYSCTL_FILE", str(conf))
        with patch("builtins.input", side_effect=["yes apply", "y"]):
            apply_fixes([{"name": "ASLR", "status": "bad", "value": "None"}])
        out = capsys.readouterr().out
        assert "Persisted" in out or "persist" in out.lower()

    def test_keyboard_interrupt_at_confirm(self, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        selected = [{"name": "ASLR", "key": "aslr",
                     "cmds": [["echo", "test"]],
                     "risky": False, "selected": True, "services": []}]
        monkeypatch.setattr("secfesc.secfetch.ui.improve._select_fixes", lambda *a: selected)
        # First the root-sudo gate (raises), so the function aborts before
        # the selection wizard.
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            apply_fixes([{"name": "ASLR", "status": "bad", "value": "None"}])

    def test_risky_fix_warning_shown_in_execution_list(self, capsys, monkeypatch):
        monkeypatch.setattr("secfesc.secfetch.ui.improve._check_firewall_available", lambda: True)
        selected = [{"name": "Modules Disabled", "key": "modules_disabled",
                     "cmds": [["sudo", "sysctl", "-w", "kernel.modules_disabled=1"]],
                     "risky": True, "selected": True, "services": []}]
        monkeypatch.setattr("secfesc.secfetch.ui.improve._select_fixes", lambda *a: selected)
        monkeypatch.setattr("secfesc.secfetch.ui.improve._run_command", lambda cmd: True)
        with patch("builtins.input", side_effect=["yes apply", "y"]):
            apply_fixes([{"name": "Modules Disabled", "status": "bad", "value": "None"}])
        out = capsys.readouterr().out
        assert "Irreversible" in out
