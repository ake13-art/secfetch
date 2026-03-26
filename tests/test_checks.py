"""
Tests for kernel security checks
"""
import pytest
from unittest.mock import patch, mock_open


class TestASLR:
    """Tests for ASLR check."""

    def test_aslr_full_enabled(self):
        """ASLR value 2 should return ok status."""
        from secfetch.checks.kernel.aslr import check
        with patch("builtins.open", mock_open(read_data="2\n")):
            result = check()
        assert result["status"] == "ok"
        assert result["value"] == "Full"

    def test_aslr_partial(self):
        """ASLR value 1 should return warn status."""
        from secfetch.checks.kernel.aslr import check
        with patch("builtins.open", mock_open(read_data="1\n")):
            result = check()
        assert result["status"] == "warn"
        assert result["value"] == "Partial"

    def test_aslr_disabled(self):
        """ASLR value 0 should return bad status."""
        from secfetch.checks.kernel.aslr import check
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check()
        assert result["status"] == "bad"
        assert result["value"] == "Disabled"

    def test_aslr_file_not_found(self):
        """Missing file should return info status."""
        from secfetch.checks.kernel.aslr import check
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = check()
        assert result["status"] == "info"


class TestTCPSyncookies:
    """Tests for TCP SYN Cookies check."""

    def test_syncookies_enabled(self):
        """SYN cookies enabled should return ok."""
        from secfetch.checks.network.tcp_syncookies import check
        with patch("builtins.open", mock_open(read_data="1\n")):
            result = check()
        assert result["status"] == "ok"
        assert result["value"] == "Enabled"

    def test_syncookies_disabled(self):
        """SYN cookies disabled should return bad."""
        from secfetch.checks.network.tcp_syncookies import check
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check()
        assert result["status"] == "bad"
        assert result["value"] == "Disabled"


class TestRPFilter:
    """Tests for Reverse Path Filter check."""

    def test_rp_filter_strict(self):
        """RP filter value 1 should return ok (strict)."""
        from secfetch.checks.network.rp_filter import check
        with patch("builtins.open", mock_open(read_data="1\n")):
            result = check()
        assert result["status"] == "ok"
        assert result["value"] == "Strict"

    def test_rp_filter_loose(self):
        """RP filter value 2 should return warn (loose)."""
        from secfetch.checks.network.rp_filter import check
        with patch("builtins.open", mock_open(read_data="2\n")):
            result = check()
        assert result["status"] == "warn"
        assert result["value"] == "Loose"

    def test_rp_filter_disabled(self):
        """RP filter value 0 should return bad."""
        from secfetch.checks.network.rp_filter import check
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check()
        assert result["status"] == "bad"
        assert result["value"] == "Disabled"


class TestIPv6:
    """Tests for IPv6 check."""

    def test_ipv6_disabled(self):
        """IPv6 disabled should return ok."""
        from secfetch.checks.network.ipv6 import check
        with patch("builtins.open", mock_open(read_data="1\n")):
            result = check()
        assert result["status"] == "ok"
        assert result["value"] == "Disabled"

    def test_ipv6_enabled(self):
        """IPv6 enabled should return info (informational only)."""
        from secfetch.checks.network.ipv6 import check
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check()
        assert result["status"] == "info"
        assert result["value"] == "Enabled"
