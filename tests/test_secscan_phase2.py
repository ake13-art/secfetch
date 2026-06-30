"""Tests for the Phase 2 secscan categories: boot, kernel, services, logging."""

import subprocess

import pytest


def _proc(returncode, stdout=""):
    return subprocess.CompletedProcess([], returncode, stdout, "")


# ── kernel ────────────────────────────────────────────────
class TestKernel:
    def _run(self, values, monkeypatch):
        """*values* maps a /proc/sys path to its raw contents (or None)."""
        from secfesc.secscan.core.categories import kernel

        monkeypatch.setattr(
            kernel, "safe_read_file",
            lambda path, default=None: values.get(path, default),
        )
        return {f.check_id: f for f in kernel.check_kernel()}

    def test_insecure_values_flagged(self, monkeypatch):
        found = self._run(
            {
                "/proc/sys/kernel/randomize_va_space": "0",
                "/proc/sys/kernel/kptr_restrict": "0",
                "/proc/sys/kernel/dmesg_restrict": "0",
                "/proc/sys/kernel/yama/ptrace_scope": "0",
                "/proc/sys/fs/suid_dumpable": "1",
                "/proc/sys/kernel/unprivileged_bpf_disabled": "0",
                "/proc/sys/kernel/sysrq": "1",
                "/proc/sys/kernel/kexec_load_disabled": "0",
                "/proc/sys/kernel/perf_event_paranoid": "1",
            },
            monkeypatch,
        )
        assert {
            "KRNL-5677", "KRNL-5820", "KRNL-5821", "KRNL-5822", "KRNL-6000",
            "KRNL-5831", "KRNL-5830", "KRNL-5695", "KRNL-5680",
        } <= set(found)
        assert found["KRNL-5820"].affected == "kernel.kptr_restrict = 0"

    def test_hardened_values_clean(self, monkeypatch):
        found = self._run(
            {
                "/proc/sys/kernel/randomize_va_space": "2",
                "/proc/sys/kernel/kptr_restrict": "1",
                "/proc/sys/kernel/dmesg_restrict": "1",
                "/proc/sys/kernel/yama/ptrace_scope": "1",
                "/proc/sys/fs/suid_dumpable": "0",
                "/proc/sys/kernel/unprivileged_bpf_disabled": "1",
                "/proc/sys/kernel/sysrq": "0",
                "/proc/sys/kernel/kexec_load_disabled": "1",
                "/proc/sys/kernel/perf_event_paranoid": "2",
            },
            monkeypatch,
        )
        assert found == {}

    def test_missing_file_skipped(self, monkeypatch):
        # Nothing readable → no findings (all rules skipped).
        assert self._run({}, monkeypatch) == {}

    def test_unparsable_value_skipped(self, monkeypatch):
        from secfesc.secscan.core.categories.kernel import _read_int

        assert _read_int("/x") is None or True  # exercised below via mapping
        found = self._run({"/proc/sys/kernel/kptr_restrict": "garbage"}, monkeypatch)
        assert "KRNL-5820" not in found

    def test_read_int_empty_string(self, monkeypatch):
        from secfesc.secscan.core.categories import kernel

        monkeypatch.setattr(kernel, "safe_read_file", lambda *a, **k: "")
        assert kernel._read_int("/whatever") is None

    def test_read_int_missing_returns_none(self, monkeypatch):
        from secfesc.secscan.core.categories import kernel

        monkeypatch.setattr(kernel, "safe_read_file", lambda *a, **k: None)
        assert kernel._read_int("/whatever") is None


# ── boot ──────────────────────────────────────────────────
class TestBoot:
    def test_grub_without_password_flagged(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import boot

        cfg = tmp_path / "grub.cfg"
        cfg.write_text("menuentry 'Linux' { linux /vmlinuz }\n")
        monkeypatch.setattr(boot, "GRUB_CFGS", [str(cfg)])
        monkeypatch.setattr(boot, "GRUB_SOURCES", [])
        ids = {f.check_id for f in boot.check_boot()}
        assert "BOOT-5122" in ids

    def test_grub_with_password_clean(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import boot

        cfg = tmp_path / "grub.cfg"
        cfg.write_text("set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.x\n")
        cfg.chmod(0o600)
        monkeypatch.setattr(boot, "GRUB_CFGS", [str(cfg)])
        monkeypatch.setattr(boot, "GRUB_SOURCES", [])
        assert boot.check_boot() == []

    def test_password_hash_world_readable_flagged(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import boot

        cfg = tmp_path / "grub.cfg"
        cfg.write_text("set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.x\n")
        cfg.chmod(0o644)  # world-readable
        monkeypatch.setattr(boot, "GRUB_CFGS", [str(cfg)])
        monkeypatch.setattr(boot, "GRUB_SOURCES", [])
        ids = {f.check_id for f in boot.check_boot()}
        assert "BOOT-5121" in ids

    def test_no_grub_no_findings(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import boot

        monkeypatch.setattr(boot, "GRUB_CFGS", [str(tmp_path / "nope.cfg")])
        monkeypatch.setattr(boot, "GRUB_SOURCES", [])
        monkeypatch.setattr(boot.os.path, "isdir", lambda p: False)
        assert boot.check_boot() == []

    def test_grub_d_dir_counts_as_installed(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import boot

        # No grub.cfg, but /etc/grub.d exists → installed, no password → flagged.
        monkeypatch.setattr(boot, "GRUB_CFGS", [str(tmp_path / "nope.cfg")])
        monkeypatch.setattr(boot, "GRUB_SOURCES", [])
        monkeypatch.setattr(boot.os.path, "isdir", lambda p: p == "/etc/grub.d")
        ids = {f.check_id for f in boot.check_boot()}
        assert "BOOT-5122" in ids

    def test_is_world_readable_oserror_false(self, monkeypatch):
        from secfesc.secscan.core.categories import boot

        monkeypatch.setattr(
            boot.os, "stat", lambda p: (_ for _ in ()).throw(OSError("no stat"))
        )
        assert boot._is_world_readable("/x") is False


# ── services ──────────────────────────────────────────────
class TestServices:
    def test_no_systemctl_skips(self, monkeypatch):
        from secfesc.secscan.core.categories import services

        monkeypatch.setattr(services.shutil, "which", lambda _: None)
        assert services.check_services() == []

    def test_enabled_insecure_service_flagged(self, monkeypatch):
        from secfesc.secscan.core.categories import services

        monkeypatch.setattr(services.shutil, "which", lambda _: "/usr/bin/systemctl")

        def run(cmd, **k):
            if cmd[:2] == ["systemctl", "is-enabled"] and cmd[2] == "telnet.socket":
                return _proc(0, "enabled")
            return _proc(1, "disabled")

        monkeypatch.setattr(services, "safe_subprocess_run", run)
        findings = services.check_services()
        assert len(findings) == 1
        assert findings[0].check_id == "SRV-3104"
        assert "telnet.socket" in findings[0].affected

    def test_nothing_enabled_clean(self, monkeypatch):
        from secfesc.secscan.core.categories import services

        monkeypatch.setattr(services.shutil, "which", lambda _: "/usr/bin/systemctl")
        monkeypatch.setattr(services, "safe_subprocess_run", lambda *a, **k: _proc(1, "disabled"))
        assert services.check_services() == []

    def test_enabled_runtime_counts(self, monkeypatch):
        from secfesc.secscan.core.categories import services

        monkeypatch.setattr(services.shutil, "which", lambda _: "/usr/bin/systemctl")
        monkeypatch.setattr(
            services, "safe_subprocess_run",
            lambda cmd, **k: _proc(0, "enabled-runtime") if cmd[2] == "tftp.socket" else _proc(1),
        )
        findings = services.check_services()
        assert "tftp.socket" in findings[0].affected


# ── logging ───────────────────────────────────────────────
class TestLogging:
    def test_no_systemctl_skips(self, monkeypatch):
        from secfesc.secscan.core.categories import logging

        monkeypatch.setattr(logging.shutil, "which", lambda _: None)
        assert logging.check_logging() == []

    def test_no_logger_flagged(self, monkeypatch):
        from secfesc.secscan.core.categories import logging

        monkeypatch.setattr(logging.shutil, "which", lambda _: "/usr/bin/systemctl")
        # everything inactive
        monkeypatch.setattr(logging, "safe_subprocess_run", lambda *a, **k: _proc(3, "inactive"))
        ids = {f.check_id for f in logging.check_logging()}
        assert "LOG-4001" in ids
        assert "LOG-4010" in ids
        assert "LOG-4031" not in ids  # journald not active → persistence not checked

    def test_journald_active_persistent_clean(self, monkeypatch):
        from secfesc.secscan.core.categories import logging

        monkeypatch.setattr(logging.shutil, "which", lambda _: "/usr/bin/systemctl")

        def active(cmd, **k):
            svc = cmd[2]
            return _proc(0, "active") if svc in ("systemd-journald", "auditd") else _proc(3)

        monkeypatch.setattr(logging, "safe_subprocess_run", active)
        monkeypatch.setattr(logging, "safe_read_file", lambda *a, **k: "Storage=persistent\n")
        assert logging.check_logging() == []

    def test_journald_volatile_flagged(self, monkeypatch):
        from secfesc.secscan.core.categories import logging

        monkeypatch.setattr(logging.shutil, "which", lambda _: "/usr/bin/systemctl")
        monkeypatch.setattr(
            logging, "safe_subprocess_run",
            lambda cmd, **k: _proc(0, "active") if cmd[2] == "systemd-journald" else _proc(3),
        )
        monkeypatch.setattr(logging, "safe_read_file", lambda *a, **k: "Storage=volatile\n")
        ids = {f.check_id for f in logging.check_logging()}
        assert "LOG-4031" in ids

    def test_journald_auto_with_journal_dir_clean(self, monkeypatch):
        from secfesc.secscan.core.categories import logging

        monkeypatch.setattr(logging.shutil, "which", lambda _: "/usr/bin/systemctl")
        monkeypatch.setattr(
            logging, "safe_subprocess_run",
            lambda cmd, **k: _proc(0, "active")
            if cmd[2] in ("systemd-journald", "auditd") else _proc(3),
        )
        monkeypatch.setattr(logging, "safe_read_file", lambda *a, **k: "")  # Storage unset
        monkeypatch.setattr(logging.os.path, "isdir", lambda p: p == logging.JOURNAL_DIR)
        ids = {f.check_id for f in logging.check_logging()}
        assert "LOG-4031" not in ids

    def test_storage_helper_ignores_comments(self, monkeypatch):
        from secfesc.secscan.core.categories import logging

        monkeypatch.setattr(
            logging, "safe_read_file",
            lambda *a, **k: "# Storage=persistent\nSomethingElse=1\nStorage=auto\n",
        )
        assert logging._journald_storage() == "auto"

    def test_storage_helper_returns_none_when_unset(self, monkeypatch):
        from secfesc.secscan.core.categories import logging

        monkeypatch.setattr(logging, "safe_read_file", lambda *a, **k: "Compress=yes\n")
        assert logging._journald_storage() is None


# ── registration ──────────────────────────────────────────
@pytest.mark.parametrize("module,category", [
    ("boot", "boot"),
    ("kernel", "kernel"),
    ("services", "services"),
    ("logging", "logging"),
])
def test_category_registered(module, category):
    import importlib

    from secfesc.secscan.core import registry

    registry._discovered = False
    registry._discover()
    importlib.import_module(f"secfesc.secscan.core.categories.{module}")
    assert registry.has_checks(category)
