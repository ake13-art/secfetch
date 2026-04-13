"""Tests for filesystem security checks: world_writable, suid_binaries, tmp."""

from unittest.mock import MagicMock, mock_open, patch


def _find_result(files, returncode=0):
    stdout = "\n".join(files) + "\n" if files else ""
    return MagicMock(returncode=returncode, stdout=stdout)


class TestWorldWritable:
    """Tests for World Writable check."""

    def test_no_files_gives_ok(self):
        """No world-writable files should return ok."""
        from secfetch.checks.filesystem.permissions import world_writable

        with patch("subprocess.run", return_value=_find_result([])):
            result = world_writable()
        assert result["status"] == "ok"
        assert "No unexpected" in result["value"]

    def test_few_files_gives_warn(self):
        """1-5 world-writable files should return warn."""
        from secfetch.checks.filesystem.permissions import world_writable

        files = [f"/usr/lib/file{i}" for i in range(3)]
        with patch("subprocess.run", return_value=_find_result(files)):
            result = world_writable()
        assert result["status"] == "warn"
        assert "3" in result["value"]

    def test_five_files_gives_warn(self):
        """Exactly 5 files is still warn (boundary: <=5 is warn)."""
        from secfetch.checks.filesystem.permissions import world_writable

        files = [f"/usr/lib/file{i}" for i in range(5)]
        with patch("subprocess.run", return_value=_find_result(files)):
            result = world_writable()
        assert result["status"] == "warn"

    def test_many_files_gives_bad(self):
        """>5 world-writable files should return bad."""
        from secfetch.checks.filesystem.permissions import world_writable

        files = [f"/usr/lib/file{i}" for i in range(6)]
        with patch("subprocess.run", return_value=_find_result(files)):
            result = world_writable()
        assert result["status"] == "bad"
        assert "6" in result["value"]

    def test_empty_lines_filtered(self):
        """Empty lines in find output should not be counted as files."""
        from secfetch.checks.filesystem.permissions import world_writable

        result_mock = MagicMock(returncode=0, stdout="\n\n\n")
        with patch("subprocess.run", return_value=result_mock):
            result = world_writable()
        assert result["status"] == "ok"


class TestSUIDBinaries:
    """Tests for SUID Binaries check (sicherheitskritische Whitelist-Logik)."""

    def test_only_known_safe_suid_gives_ok(self):
        """Known safe SUID binaries (/usr/bin/sudo, /usr/bin/passwd) should return ok."""
        from secfetch.checks.filesystem.permissions import suid_binaries

        files = ["/usr/bin/sudo", "/usr/bin/passwd"]
        with patch("subprocess.run", return_value=_find_result(files)):
            result = suid_binaries()
        assert result["status"] == "ok"
        assert "all expected" in result["value"]

    def test_unknown_suid_gives_warn(self):
        """1-3 unexpected SUID binaries should return warn."""
        from secfetch.checks.filesystem.permissions import suid_binaries

        files = ["/usr/bin/sudo", "/opt/custom/suspicious_bin"]
        with patch("subprocess.run", return_value=_find_result(files)):
            result = suid_binaries()
        assert result["status"] == "warn"
        assert "1" in result["value"]

    def test_many_unknown_gives_bad(self):
        """>3 unexpected SUID binaries should return bad."""
        from secfetch.checks.filesystem.permissions import suid_binaries

        files = [f"/opt/unknown/bin{i}" for i in range(4)]
        with patch("subprocess.run", return_value=_find_result(files)):
            result = suid_binaries()
        assert result["status"] == "bad"

    def test_basename_whitelist_works(self):
        """A SUID binary not in safe_suid_paths but with a safe basename should be ok."""
        from secfetch.checks.filesystem.permissions import suid_binaries

        # /bin/sudo is not in safe_suid_paths set, but basename 'sudo' is in safe_suid_names
        files = ["/bin/sudo"]
        with patch("subprocess.run", return_value=_find_result(files)):
            result = suid_binaries()
        assert result["status"] == "ok"

    def test_empty_output_gives_ok(self):
        """No SUID binaries found should return ok."""
        from secfetch.checks.filesystem.permissions import suid_binaries

        with patch("subprocess.run", return_value=_find_result([])):
            result = suid_binaries()
        assert result["status"] == "ok"
        assert "0 SUID" in result["value"]

    def test_all_known_safe_binaries_accepted(self):
        """All entries from safe_suid_paths should produce ok status."""
        from secfetch.checks.filesystem.permissions import suid_binaries

        files = [
            "/usr/bin/sudo",
            "/bin/su",
            "/usr/bin/passwd",
            "/usr/bin/gpasswd",
            "/usr/bin/newgrp",
            "/bin/mount",
            "/bin/umount",
            "/bin/ping",
        ]
        with patch("subprocess.run", return_value=_find_result(files)):
            result = suid_binaries()
        assert result["status"] == "ok"


class TestTmpNoexec:
    """Tests for /tmp noexec check."""

    def test_noexec_mounted_gives_ok(self):
        """/tmp mounted with noexec should return ok."""
        from secfetch.checks.filesystem.permissions import tmp_noexec

        mounts = "tmpfs /tmp tmpfs rw,noexec,nosuid,nodev 0 0\n"
        with patch("builtins.open", mock_open(read_data=mounts)):
            result = tmp_noexec()
        assert result["status"] == "ok"
        assert "noexec" in result["value"]

    def test_exec_allowed_gives_bad(self):
        """/tmp mounted without noexec should return bad."""
        from secfetch.checks.filesystem.permissions import tmp_noexec

        mounts = "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
        with patch("builtins.open", mock_open(read_data=mounts)):
            result = tmp_noexec()
        assert result["status"] == "bad"
        assert "allows execution" in result["value"]

    def test_tmp_not_separately_mounted_gives_warn(self):
        """If /tmp has no own mount entry, return warn."""
        from secfetch.checks.filesystem.permissions import tmp_noexec

        mounts = "ext4 / ext4 rw,relatime 0 0\ntmpfs /run tmpfs rw 0 0\n"
        with patch("builtins.open", mock_open(read_data=mounts)):
            result = tmp_noexec()
        assert result["status"] == "warn"
        assert "not separately mounted" in result["value"]

    def test_file_not_found_returns_info(self):
        """Missing /proc/mounts should return info status."""
        from secfetch.checks.filesystem.permissions import tmp_noexec

        with patch("builtins.open", side_effect=FileNotFoundError):
            result = tmp_noexec()
        assert result["status"] == "info"


class TestStickyTmp:
    """Tests for /tmp Sticky Bit check."""

    def test_sticky_bit_set_gives_ok(self):
        """Sticky bit on /tmp should return ok."""
        from secfetch.checks.filesystem.permissions import sticky_tmp

        mock_stat = MagicMock()
        mock_stat.st_mode = 0o1777  # sticky bit set
        with patch("pathlib.Path.exists", return_value=True), patch(
            "pathlib.Path.stat", return_value=mock_stat
        ):
            result = sticky_tmp()
        assert result["status"] == "ok"
        assert "sticky bit" in result["value"]

    def test_sticky_bit_missing_gives_bad(self):
        """Missing sticky bit on /tmp should return bad."""
        from secfetch.checks.filesystem.permissions import sticky_tmp

        mock_stat = MagicMock()
        mock_stat.st_mode = 0o0777  # no sticky bit
        with patch("pathlib.Path.exists", return_value=True), patch(
            "pathlib.Path.stat", return_value=mock_stat
        ):
            result = sticky_tmp()
        assert result["status"] == "bad"
        assert "missing" in result["value"]

    def test_tmp_not_exists_gives_warn(self):
        """/tmp not existing should return warn."""
        from secfetch.checks.filesystem.permissions import sticky_tmp

        with patch("pathlib.Path.exists", return_value=False):
            result = sticky_tmp()
        assert result["status"] == "warn"
        assert "does not exist" in result["value"]

    def test_permission_error_returns_info(self):
        """PermissionError when accessing /tmp should return info."""
        from secfetch.checks.filesystem.permissions import sticky_tmp

        with patch("pathlib.Path.exists", return_value=True), patch(
            "pathlib.Path.stat", side_effect=PermissionError
        ):
            result = sticky_tmp()
        assert result["status"] == "info"
