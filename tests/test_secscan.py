"""Tests for the secscan audit framework and Phase 1 checks (ssh/users/groups)."""

import os
from unittest.mock import patch

from secfesc.secscan.core.engine import AuditEngine, AuditFinding


# ── registry ──────────────────────────────────────────────
class TestRegistry:
    def test_audit_check_registers_and_runs(self):
        from secfesc.secscan.core import registry

        @registry.audit_check("unittest-cat")
        def _dummy():
            return AuditFinding(
                category="unittest-cat",
                check_id="T-1",
                title="t",
                severity="low",
                status="found",
                description="d",
                solution="s",
            )

        registry._discovered = True  # skip filesystem discovery for this synthetic category
        findings = registry.run_category("unittest-cat")
        assert any(f.check_id == "T-1" for f in findings)

    def test_failing_check_becomes_error_finding(self):
        from secfesc.secscan.core import registry

        @registry.audit_check("unittest-boom")
        def _boom():
            raise RuntimeError("kaboom")

        registry._discovered = True
        findings = registry.run_category("unittest-boom")
        assert len(findings) == 1
        assert findings[0].status == "error"
        assert "kaboom" in findings[0].description

    def test_list_or_none_results(self):
        from secfesc.secscan.core import registry

        @registry.audit_check("unittest-list")
        def _none():
            return None

        @registry.audit_check("unittest-list")
        def _list():
            return [
                AuditFinding("unittest-list", "L-1", "a", "low", "found", "d", "s"),
                AuditFinding("unittest-list", "L-2", "b", "low", "found", "d", "s"),
            ]

        registry._discovered = True
        findings = registry.run_category("unittest-list")
        assert {f.check_id for f in findings} == {"L-1", "L-2"}


# ── ssh ───────────────────────────────────────────────────
class TestSSH:
    def _run(self, config_text):
        from secfesc.secscan.core.categories import ssh

        with patch.object(ssh, "_ssh_installed", return_value=True), patch.object(
            ssh, "_load_config", return_value=ssh._parse(config_text)
        ):
            return {f.check_id: f for f in ssh.check_ssh()}

    def test_parse_first_occurrence_wins(self):
        from secfesc.secscan.core.categories import ssh

        cfg = ssh._parse("PermitRootLogin yes\n# comment\nPermitRootLogin no\n")
        assert cfg["permitrootlogin"] == "yes"

    def test_root_login_yes_is_high(self):
        found = self._run("PermitRootLogin yes\n")
        assert found["SSH-7412"].severity == "high"

    def test_permit_root_default_is_low_note(self):
        found = self._run("")  # absent -> prohibit-password default
        assert "SSH-7413" in found
        assert found["SSH-7413"].severity == "low"

    def test_empty_passwords_flagged(self):
        found = self._run("PermitEmptyPasswords yes\n")
        assert found["SSH-7408"].severity == "high"

    def test_protocol_1_flagged(self):
        found = self._run("Protocol 2,1\n")
        assert "SSH-7401" in found

    def test_not_installed_returns_nothing(self):
        from secfesc.secscan.core.categories import ssh

        with patch.object(ssh, "_ssh_installed", return_value=False):
            assert ssh.check_ssh() == []


# ── users ─────────────────────────────────────────────────
class TestUsers:
    def _run(self, passwd, shadow="", is_root=False):
        from secfesc.secscan.core.categories import users

        def fake_read(path, default=""):
            if path == "/etc/passwd":
                return passwd
            if path == "/etc/shadow":
                return shadow
            return default

        with patch.object(users, "safe_read_file", side_effect=fake_read), patch(
            "secfesc.secscan.core.categories.users.os.geteuid", return_value=0 if is_root else 1000
        ):
            return {f.check_id: f for f in users.check_users()}

    def test_extra_uid0_account_is_high(self):
        passwd = "root:x:0:0::/root:/bin/bash\nbackdoor:x:0:0::/home/b:/bin/bash\n"
        found = self._run(passwd)
        assert found["USER-7201"].severity == "high"
        assert "backdoor" in found["USER-7201"].affected

    def test_duplicate_uid_flagged(self):
        passwd = "alice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1000:1001::/home/bob:/bin/bash\n"
        found = self._run(passwd)
        assert "USER-7202" in found

    def test_empty_password_only_with_root(self):
        passwd = "ghost:x:1001:1001::/home/ghost:/bin/bash\n"
        shadow = "ghost::19000:0:99999:7:::\n"
        assert "USER-7204" not in self._run(passwd, shadow, is_root=False)
        assert "USER-7204" in self._run(passwd, shadow, is_root=True)


# ── groups ────────────────────────────────────────────────
class TestGroups:
    def _run(self, group_text):
        from secfesc.secscan.core.categories import groups

        with patch.object(groups, "safe_read_file", return_value=group_text):
            return {f.check_id: f for f in groups.check_groups()}

    def test_duplicate_gid_flagged(self):
        found = self._run("admins:x:1000:\nstaff:x:1000:\n")
        assert "GROUP-7301" in found

    def test_extra_root_group_member(self):
        found = self._run("root:x:0:eve\n")
        assert "GROUP-7303" in found
        assert "eve" in found["GROUP-7303"].affected

    def test_clean_group_file_no_findings(self):
        assert self._run("root:x:0:\nusers:x:100:\n") == {}


# ── engine integration ────────────────────────────────────
class TestEngine:
    def test_run_categories_collects_findings(self):
        from secfesc.secscan.core import registry

        engine = AuditEngine()
        with patch.object(
            registry,
            "run_category",
            return_value=[AuditFinding("ssh", "X-1", "t", "high", "found", "d", "s")],
        ), patch.object(registry, "has_checks", return_value=True):
            report = engine.run_categories(["ssh"])
        assert len(report.findings) == 1
        assert report.end_time is not None

    def test_severity_counts(self):
        from datetime import datetime

        from secfesc.secscan.core.engine import AuditReport

        report = AuditReport(hostname="h", start_time=datetime.now())
        report.findings = [
            AuditFinding("c", "1", "t", "high", "found", "d", "s"),
            AuditFinding("c", "2", "t", "medium", "found", "d", "s"),
            AuditFinding("c", "3", "t", "low", "found", "d", "s"),
        ]
        counts = AuditEngine._severity_counts(report)
        assert counts == {"errors": 1, "warnings": 1, "notes": 1}

    def test_print_summary_smoke(self, capsys):
        from datetime import datetime

        from secfesc.secscan.core.engine import AuditReport

        report = AuditReport(
            hostname="h", start_time=datetime.now(), end_time=datetime.now()
        )
        report.findings = [
            AuditFinding("ssh", "S-1", "Title", "high", "found", "Desc", "Fix", "the thing")
        ]
        report.warnings = ["Skipped 'kernel' (run as root to include it)"]
        AuditEngine().print_summary(report)
        out = capsys.readouterr().out
        assert "S-1" in out
        assert "the thing" in out  # affected line rendered
        assert "Skipped 'kernel'" in out  # warning rendered

    def test_print_findings_empty(self, capsys):
        from datetime import datetime

        from secfesc.secscan.core.engine import AuditReport

        AuditEngine().print_findings(
            AuditReport(hostname="h", start_time=datetime.now())
        )
        assert "No findings" in capsys.readouterr().out

    def test_get_hostname_falls_back_to_unknown(self, monkeypatch):
        monkeypatch.setattr(os, "uname", lambda: (_ for _ in ()).throw(Exception("no uname")))
        engine = AuditEngine()
        assert engine.report.hostname == "unknown"

    def test_run_categories_skips_unregistered_category(self, monkeypatch):
        from secfesc.secscan.core import registry
        monkeypatch.setattr(registry, "has_checks", lambda cat: False)
        report = AuditEngine().run_categories(["nonexistent_xyz"])
        assert report.findings == []

    def test_run_categories_skips_root_only_as_non_root(self, monkeypatch):
        from secfesc.secscan.core import registry
        monkeypatch.setattr(registry, "has_checks", lambda cat: True)
        monkeypatch.setattr(registry, "run_category", lambda cat: [])
        engine = AuditEngine()
        engine.report.is_root = False
        report = engine.run_categories(["files"])  # "files" is in root_categories
        assert any("files" in w for w in report.warnings)

    def test_run_full_audit_delegates_to_run_categories(self, monkeypatch):
        from secfesc.secscan.core import registry
        monkeypatch.setattr(registry, "registered_categories", lambda: ["ssh"])
        monkeypatch.setattr(registry, "has_checks", lambda cat: True)
        monkeypatch.setattr(registry, "run_category", lambda cat: [])
        report = AuditEngine().run_full_audit()
        assert report is not None

    def test_run_quick_audit_completes(self, monkeypatch):
        from secfesc.secscan.core import registry
        monkeypatch.setattr(registry, "has_checks", lambda cat: False)
        report = AuditEngine().run_quick_audit()
        assert report is not None
        assert report.findings == []


# ── registry additional ───────────────────────────────────
class TestRegistryAdditional:
    def test_registered_categories_returns_sorted_list(self):
        from secfesc.secscan.core import registry
        cats = registry.registered_categories()
        assert isinstance(cats, list)
        assert cats == sorted(cats)
        assert len(cats) > 0


# ── cli exit codes ────────────────────────────────────────
class TestCLIExitCodes:
    def _report(self, severities):
        from datetime import datetime

        from secfesc.secscan.core.engine import AuditReport

        report = AuditReport(
            hostname="h", start_time=datetime.now(), end_time=datetime.now()
        )
        report.findings = [
            AuditFinding("c", str(i), "t", sev, "found", "d", "s")
            for i, sev in enumerate(severities)
        ]
        return report

    def _run(self, severities):
        from secfesc.secscan import cli

        with patch(
            "secfesc.secscan.core.engine.AuditEngine.run_quick_audit",
            return_value=self._report(severities),
        ):
            return cli.main([])

    def test_clean_returns_0(self):
        assert self._run([]) == 0

    def test_warning_returns_1(self):
        assert self._run(["medium", "low"]) == 1

    def test_error_returns_2(self):
        assert self._run(["high", "medium"]) == 2


# ── cli flags ─────────────────────────────────────────────
class TestCLIFlags:
    """Cover the --full / --category / --quick / --verbose / --quiet / --report paths."""

    def _empty_report(self):
        from datetime import datetime

        from secfesc.secscan.core.engine import AuditReport
        return AuditReport(hostname="h", start_time=datetime.now(), end_time=datetime.now())

    def test_full_flag_calls_run_full_audit(self, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        called = []
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_full_audit", lambda self: called.append(1) or r)
        monkeypatch.setattr(AuditEngine, "print_summary", lambda self, r: None)
        cli.main(["--full"])
        assert called

    def test_category_flag_calls_run_categories(self, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        called = []
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_categories",
                            lambda self, cats: called.append(cats) or r)
        monkeypatch.setattr(AuditEngine, "print_summary", lambda self, rpt: None)
        cli.main(["--category", "ssh"])
        assert called == [["ssh"]]

    def test_quick_flag_calls_run_quick_audit(self, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        called = []
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_quick_audit", lambda self: called.append(1) or r)
        monkeypatch.setattr(AuditEngine, "print_summary", lambda self, rpt: None)
        cli.main(["--quick"])
        assert called

    def test_verbose_flag_does_not_crash(self, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_quick_audit", lambda self: r)
        monkeypatch.setattr(AuditEngine, "print_summary", lambda self, rpt: None)
        assert cli.main(["--verbose"]) == 0

    def test_quiet_flag_suppresses_summary(self, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        printed = []
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_quick_audit", lambda self: r)
        monkeypatch.setattr(AuditEngine, "print_summary", lambda self, rpt: printed.append(1))
        cli.main(["--quiet"])
        assert not printed

    def test_report_json_to_stdout(self, capsys, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_quick_audit", lambda self: r)
        cli.main(["--report", "json"])
        out = capsys.readouterr().out
        import json
        data = json.loads(out)
        assert "findings" in data

    def test_report_csv_to_stdout(self, capsys, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_quick_audit", lambda self: r)
        cli.main(["--report", "csv"])
        out = capsys.readouterr().out
        assert "Category" in out

    def test_report_html_to_stdout(self, capsys, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_quick_audit", lambda self: r)
        cli.main(["--report", "html"])
        out = capsys.readouterr().out
        assert "<html" in out.lower()

    def test_report_json_to_file(self, tmp_path, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_quick_audit", lambda self: r)
        monkeypatch.setattr(AuditEngine, "print_summary", lambda self, rpt: None)
        out_file = tmp_path / "report.json"
        cli.main(["--report", "json", "--output", str(out_file)])
        import json
        assert "findings" in json.loads(out_file.read_text())

    def test_report_to_stdout_suppresses_human_summary(self, capsys, monkeypatch):
        from secfesc.secscan import cli
        from secfesc.secscan.core.engine import AuditEngine
        printed = []
        r = self._empty_report()
        monkeypatch.setattr(AuditEngine, "run_quick_audit", lambda self: r)
        monkeypatch.setattr(AuditEngine, "print_summary", lambda self, rpt: printed.append(1))
        cli.main(["--report", "json"])
        assert not printed  # human summary suppressed when exporting to stdout
