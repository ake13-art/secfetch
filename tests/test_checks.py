"""Tests for security checks."""
from unittest.mock import mock_open, patch


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


class TestHardening:
    """Tests for kernel hardening checks."""

    def test_kptr_restrict_full(self):
        from secfetch.checks.kernel.hardening import check_kptr
        with patch("builtins.open", mock_open(read_data="2\n")):
            result = check_kptr()
        assert result["status"] == "ok"
        assert result["value"] == "Fully Restricted"

    def test_kptr_restrict_disabled(self):
        from secfetch.checks.kernel.hardening import check_kptr
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check_kptr()
        assert result["status"] == "bad"

    def test_kptr_restrict_missing(self):
        from secfetch.checks.kernel.hardening import check_kptr
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = check_kptr()
        assert result["status"] == "info"
        assert result["value"] == "not available"

    def test_dmesg_restrict_enabled(self):
        from secfetch.checks.kernel.hardening import check_dmesg
        with patch("builtins.open", mock_open(read_data="1\n")):
            result = check_dmesg()
        assert result["status"] == "ok"

    def test_dmesg_restrict_disabled(self):
        from secfetch.checks.kernel.hardening import check_dmesg
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check_dmesg()
        assert result["status"] == "bad"

    def test_ptrace_scope_restricted(self):
        from secfetch.checks.kernel.hardening import check_ptrace
        with patch("builtins.open", mock_open(read_data="1\n")):
            result = check_ptrace()
        assert result["status"] == "ok"
        assert result["value"] == "Restricted"

    def test_ptrace_scope_unrestricted(self):
        from secfetch.checks.kernel.hardening import check_ptrace
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check_ptrace()
        assert result["status"] == "bad"

    def test_bpf_disabled(self):
        from secfetch.checks.kernel.hardening import check_bpf
        with patch("builtins.open", mock_open(read_data="1\n")):
            result = check_bpf()
        assert result["status"] == "ok"

    def test_bpf_enabled(self):
        from secfetch.checks.kernel.hardening import check_bpf
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check_bpf()
        assert result["status"] == "bad"

    def test_modules_disabled(self):
        from secfetch.checks.kernel.hardening import check_modules
        with patch("builtins.open", mock_open(read_data="1\n")):
            result = check_modules()
        assert result["status"] == "ok"

    def test_modules_enabled(self):
        from secfetch.checks.kernel.hardening import check_modules
        with patch("builtins.open", mock_open(read_data="0\n")):
            result = check_modules()
        assert result["status"] == "warn"


class TestLockdown:
    """Tests for lockdown check."""

    def test_integrity(self):
        from secfetch.checks.kernel.lockdown import check
        with patch("builtins.open", mock_open(read_data="none [integrity] confidentiality\n")):
            result = check()
        assert result["status"] == "ok"
        assert result["value"] == "integrity"

    def test_none(self):
        from secfetch.checks.kernel.lockdown import check
        with patch("builtins.open", mock_open(read_data="[none] integrity confidentiality\n")):
            result = check()
        assert result["status"] == "warn"
        assert result["value"] == "none"

    def test_file_missing(self):
        from secfetch.checks.kernel.lockdown import check
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = check()
        assert result["status"] == "info"


class TestLSM:
    """Tests for LSM check."""

    def test_with_modules(self):
        from secfetch.checks.kernel.lsm import check
        with patch("builtins.open", mock_open(read_data="lockdown,capability,landlock,yama,apparmor\n")):
            result = check()
        assert result["status"] == "ok"

    def test_empty(self):
        from secfetch.checks.kernel.lsm import check
        with patch("builtins.open", mock_open(read_data="\n")):
            result = check()
        assert result["status"] == "warn"

    def test_file_missing(self):
        from secfetch.checks.kernel.lsm import check
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = check()
        assert result["status"] == "info"


class TestSecureBoot:
    """Tests for Secure Boot check."""

    def test_enabled(self):
        from secfetch.checks.system.secureboot import check
        with patch("os.path.exists", return_value=True), \
             patch("glob.glob", return_value=["/sys/firmware/efi/efivars/SecureBoot-xxx"]), \
             patch("builtins.open", mock_open(read_data=b"\x06\x00\x00\x00\x01")):
            result = check()
        assert result["status"] == "ok"
        assert result["value"] == "Enabled"

    def test_disabled(self):
        from secfetch.checks.system.secureboot import check
        with patch("os.path.exists", return_value=True), \
             patch("glob.glob", return_value=["/sys/firmware/efi/efivars/SecureBoot-xxx"]), \
             patch("builtins.open", mock_open(read_data=b"\x06\x00\x00\x00\x00")):
            result = check()
        assert result["status"] == "bad"
        assert result["value"] == "Disabled"

    def test_legacy_bios(self):
        from secfetch.checks.system.secureboot import check
        with patch("os.path.exists", return_value=False):
            result = check()
        assert result["status"] == "warn"
        assert "Legacy BIOS" in result["value"]

    def test_no_efivar(self):
        from secfetch.checks.system.secureboot import check
        with patch("os.path.exists", return_value=True), \
             patch("glob.glob", return_value=[]):
            result = check()
        assert result["status"] == "warn"
