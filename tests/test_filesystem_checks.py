"""Tests for filesystem security checks: world_writable, suid_binaries, tmp."""

from unittest.mock import MagicMock, patch


def _find_result(files_with_perms, returncode=0):
    """Build a fake CompletedProcess-like result for the find scan.

    *files_with_perms* is an iterable of (perm_octal_str, path) pairs — the
    exact format `_scan_filesystem` parses via `find -printf "%m %p\\n"`.
    """
    lines = [f"{perm} {path}" for perm, path in files_with_perms]
    stdout = "\n".join(lines) + "\n" if lines else ""
    return MagicMock(returncode=returncode, stdout=stdout)


def _patched_find(files_with_perms, returncode=0):
    result = _find_result(files_with_perms, returncode=returncode)
    return patch(
        "secfesc.checks.filesystem.permissions.safe_subprocess_run",
        return_value=result,
    )


class TestWorldWritable:
    """Tests for World Writable check."""

    def test_no_files_gives_ok(self):
        """No world-writable files should return ok."""
        from secfesc.checks.filesystem.permissions import world_writable

        with _patched_find([]):
            result = world_writable()
        assert result["status"] == "ok"
        assert "No unexpected" in result["value"]

    def test_few_files_gives_warn(self):
        """1-5 world-writable files should return warn."""
        from secfesc.checks.filesystem.permissions import world_writable

        files = [("0666", f"/usr/lib/file{i}") for i in range(3)]
        with _patched_find(files):
            result = world_writable()
        assert result["status"] == "warn"
        assert "3" in result["value"]

    def test_five_files_gives_warn(self):
        """Exactly 5 files is still warn (boundary: <=5 is warn)."""
        from secfesc.checks.filesystem.permissions import world_writable

        files = [("0666", f"/usr/lib/file{i}") for i in range(5)]
        with _patched_find(files):
            result = world_writable()
        assert result["status"] == "warn"

    def test_many_files_gives_bad(self):
        """>5 world-writable files should return bad."""
        from secfesc.checks.filesystem.permissions import world_writable

        files = [("0666", f"/usr/lib/file{i}") for i in range(6)]
        with _patched_find(files):
            result = world_writable()
        assert result["status"] == "bad"
        assert "6" in result["value"]

    def test_empty_lines_filtered(self):
        """Empty lines in find output should not be counted as files."""
        from secfesc.checks.filesystem.permissions import world_writable

        result_mock = MagicMock(returncode=0, stdout="\n\n\n")
        with patch(
            "secfesc.checks.filesystem.permissions.safe_subprocess_run",
            return_value=result_mock,
        ):
            result = world_writable()
        assert result["status"] == "ok"

    def test_find_returncode_1_partial_success(self):
        """find exits with code 1 when some paths are unreadable — normal."""
        from secfesc.checks.filesystem.permissions import world_writable

        files = [("0666", "/usr/lib/file0"), ("0666", "/usr/lib/file1")]
        with _patched_find(files, returncode=1):
            result = world_writable()
        assert result["status"] == "warn"
        assert "2" in result["value"]

    def test_find_returncode_2_fatal_returns_ok_with_zero(self):
        """A fatal find error (returncode > 1) yields no findings."""
        from secfesc.checks.filesystem.permissions import world_writable

        with _patched_find([("0666", "/usr/lib/file0")], returncode=2):
            result = world_writable()
        assert result["status"] == "ok"


class TestSUIDBinaries:
    """Tests for SUID Binaries check (sicherheitskritische Whitelist-Logik)."""

    def test_only_known_safe_suid_gives_ok(self):
        """Known safe SUID binaries (/usr/bin/sudo, /usr/bin/passwd) should return ok."""
        from secfesc.checks.filesystem.permissions import suid_binaries

        files = [("4755", "/usr/bin/sudo"), ("4755", "/usr/bin/passwd")]
        with _patched_find(files):
            result = suid_binaries()
        assert result["status"] == "ok"
        assert "all expected" in result["value"]

    def test_unknown_suid_gives_warn(self):
        """1-3 unexpected SUID binaries should return warn."""
        from secfesc.checks.filesystem.permissions import suid_binaries

        files = [("4755", "/usr/bin/sudo"), ("4755", "/opt/custom/suspicious_bin")]
        with _patched_find(files):
            result = suid_binaries()
        assert result["status"] == "warn"
        assert "1" in result["value"]

    def test_many_unknown_gives_bad(self):
        """>3 unexpected SUID binaries should return bad."""
        from secfesc.checks.filesystem.permissions import suid_binaries

        files = [("4755", f"/opt/unknown/bin{i}") for i in range(4)]
        with _patched_find(files):
            result = suid_binaries()
        assert result["status"] == "bad"

    def test_basename_whitelist_works(self):
        """A SUID binary not in safe_suid_paths but with a safe basename should be ok."""
        from secfesc.checks.filesystem.permissions import suid_binaries

        files = [("4755", "/bin/sudo")]
        with _patched_find(files):
            result = suid_binaries()
        assert result["status"] == "ok"

    def test_empty_output_gives_ok(self):
        """No SUID binaries found should return ok."""
        from secfesc.checks.filesystem.permissions import suid_binaries

        with _patched_find([]):
            result = suid_binaries()
        assert result["status"] == "ok"
        assert "0 SUID" in result["value"]

    def test_all_known_safe_binaries_accepted(self):
        """All entries from safe_suid_paths should produce ok status."""
        from secfesc.checks.filesystem.permissions import suid_binaries

        files = [
            ("4755", "/usr/bin/sudo"),
            ("4755", "/bin/su"),
            ("4755", "/usr/bin/passwd"),
            ("4755", "/usr/bin/gpasswd"),
            ("4755", "/usr/bin/newgrp"),
            ("4755", "/bin/mount"),
            ("4755", "/bin/umount"),
            ("4755", "/bin/ping"),
        ]
        with _patched_find(files):
            result = suid_binaries()
        assert result["status"] == "ok"


class TestTmpNoexec:
    """Tests for /tmp noexec check."""

    def test_noexec_mounted_gives_ok(self):
        """/tmp mounted with noexec should return ok."""
        from secfesc.checks.filesystem.permissions import tmp_noexec

        mounts = "tmpfs /tmp tmpfs rw,noexec,nosuid,nodev 0 0\n"
        with patch("pathlib.Path.read_text", return_value=mounts):
            result = tmp_noexec()
        assert result["status"] == "ok"
        assert "noexec" in result["value"]

    def test_exec_allowed_gives_bad(self):
        """/tmp mounted without noexec should return bad."""
        from secfesc.checks.filesystem.permissions import tmp_noexec

        mounts = "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
        with patch("pathlib.Path.read_text", return_value=mounts):
            result = tmp_noexec()
        assert result["status"] == "bad"
        assert "allows execution" in result["value"]

    def test_tmp_not_separately_mounted_gives_warn(self):
        """If /tmp has no own mount entry, return warn."""
        from secfesc.checks.filesystem.permissions import tmp_noexec

        mounts = "ext4 / ext4 rw,relatime 0 0\ntmpfs /run tmpfs rw 0 0\n"
        with patch("pathlib.Path.read_text", return_value=mounts):
            result = tmp_noexec()
        assert result["status"] == "warn"
        assert "not separately mounted" in result["value"]

    def test_file_not_found_returns_info(self):
        """Missing /proc/mounts should return info status."""
        from secfesc.checks.filesystem.permissions import tmp_noexec

        with patch("pathlib.Path.read_text", side_effect=OSError("not found")):
            result = tmp_noexec()
        assert result["status"] == "info"


class TestStickyTmp:
    """Tests for /tmp Sticky Bit check."""

    def test_sticky_bit_set_gives_ok(self):
        """Sticky bit on /tmp should return ok."""
        from secfesc.checks.filesystem.permissions import sticky_tmp

        mock_lstat = MagicMock()
        mock_lstat.st_mode = 0o1777  # sticky bit set
        with patch("pathlib.Path.lstat", return_value=mock_lstat):
            result = sticky_tmp()
        assert result["status"] == "ok"
        assert "sticky bit" in result["value"]

    def test_sticky_bit_missing_gives_bad(self):
        """Missing sticky bit on /tmp should return bad."""
        from secfesc.checks.filesystem.permissions import sticky_tmp

        mock_lstat = MagicMock()
        mock_lstat.st_mode = 0o0777  # no sticky bit
        with patch("pathlib.Path.lstat", return_value=mock_lstat):
            result = sticky_tmp()
        assert result["status"] == "bad"
        assert "missing" in result["value"]

    def test_tmp_lstat_oserror_returns_warn(self):
        """OSError on lstat() should return warn."""
        from secfesc.checks.filesystem.permissions import sticky_tmp

        with patch("pathlib.Path.lstat", side_effect=OSError("no such file")):
            result = sticky_tmp()
        assert result["status"] == "warn"
        assert "does not exist" in result["value"]

    def test_permission_error_returns_warn(self):
        """PermissionError on lstat() falls through OSError to warn."""
        from secfesc.checks.filesystem.permissions import sticky_tmp

        with patch("pathlib.Path.lstat", side_effect=PermissionError):
            result = sticky_tmp()
        assert result["status"] == "warn"
