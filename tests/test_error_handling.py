"""Tests for error handling utilities."""
import subprocess

from secfetch.core.error_handling import handle_check_errors, safe_read_file, safe_subprocess_run


class TestHandleCheckErrors:
    """Tests for the @handle_check_errors decorator."""

    def test_successful_function(self):
        @handle_check_errors
        def good_check():
            return {"status": "ok", "value": "test"}
        assert good_check() == {"status": "ok", "value": "test"}

    def test_file_not_found(self):
        @handle_check_errors
        def bad_check():
            raise FileNotFoundError()
        result = bad_check()
        assert result["status"] == "info"
        assert result["value"] == "not available"

    def test_permission_error(self):
        @handle_check_errors
        def bad_check():
            raise PermissionError()
        result = bad_check()
        assert result["status"] == "info"
        assert result["value"] == "not available"

    def test_timeout_expired(self):
        @handle_check_errors
        def bad_check():
            raise subprocess.TimeoutExpired(cmd="test", timeout=5)
        result = bad_check()
        assert result["status"] == "info"
        assert result["value"] == "scan timeout"

    def test_called_process_error(self):
        @handle_check_errors
        def bad_check():
            raise subprocess.CalledProcessError(1, "test")
        result = bad_check()
        assert result["status"] == "info"
        assert result["value"] == "check unavailable"

    def test_generic_exception(self):
        @handle_check_errors
        def bad_check():
            raise RuntimeError("unexpected")
        result = bad_check()
        assert result["status"] == "info"
        assert result["value"] == "check unavailable"


class TestSafeReadFile:
    """Tests for safe_read_file."""

    def test_reads_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello\n")
        assert safe_read_file(str(f)) == "hello"

    def test_missing_file_returns_default(self):
        assert safe_read_file("/nonexistent/path") == "not available"

    def test_missing_file_custom_default(self):
        assert safe_read_file("/nonexistent/path", default="custom") == "custom"

    def test_missing_file_none_default(self):
        assert safe_read_file("/nonexistent/path", default=None) is None


class TestSafeSubprocessRun:
    """Tests for safe_subprocess_run."""

    def test_successful_command(self):
        result = safe_subprocess_run(["echo", "hello"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_missing_command(self):
        result = safe_subprocess_run(["nonexistent_command_xyz"])
        assert result.returncode == -1
        assert "command not found" in result.stderr

    def test_timeout(self):
        result = safe_subprocess_run(["sleep", "10"], timeout=1)
        assert result.returncode == -1
        assert "timeout" in result.stderr
