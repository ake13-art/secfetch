"""Tests for network security checks: ports, services, firewall."""

import subprocess
from unittest.mock import patch


def _ss_result(stdout, returncode=0):
    return subprocess.CompletedProcess(["ss", "-tulnp"], returncode, stdout, "")


def _systemctl_result(service_names, returncode=0):
    stdout = "\n".join(
        f"{svc}.service  loaded active running Some Description" for svc in service_names
    )
    return subprocess.CompletedProcess(["systemctl"], returncode, stdout, "")


def _firewall_result(stdout, returncode=0):
    return subprocess.CompletedProcess(["sudo", "ufw", "status"], returncode, stdout, "")


class TestOpenPorts:
    """Tests for Open Ports check (checks/network/ports.py)."""

    def test_suspicious_port_gives_bad(self):
        """Port classified as suspicious (e.g. Telnet/23) should return bad."""
        from secfesc.checks.network.ports import check

        ss_out = "Netid State Recv-Q Send-Q Local Address:Port\ntcp LISTEN 0 128 0.0.0.0:23\n"
        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run", return_value=_ss_result(ss_out)
        ), patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("Telnet", "suspicious")):
            result = check()
        assert result["status"] == "bad"

    def test_unnecessary_port_gives_warn(self):
        """Port classified as unnecessary (e.g. FTP/21) should return warn."""
        from secfesc.checks.network.ports import check

        ss_out = "Netid State Recv-Q Send-Q Local Address:Port\ntcp LISTEN 0 128 0.0.0.0:21\n"
        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run", return_value=_ss_result(ss_out)
        ), patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("FTP", "unnecessary")):
            result = check()
        assert result["status"] == "warn"

    def test_expected_ports_give_ok(self):
        """Only expected ports (SSH/22, HTTP/80) should return ok."""
        from secfesc.checks.network.ports import check

        ss_out = (
            "Netid State Recv-Q Send-Q Local Address:Port\n"
            "tcp LISTEN 0 128 0.0.0.0:22\n"
            "tcp LISTEN 0 128 0.0.0.0:80\n"
        )
        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run", return_value=_ss_result(ss_out)
        ), patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("HTTP", "expected")):
            result = check()
        assert result["status"] == "ok"

    def test_ss_failure_returns_unavailable(self):
        """ss command failure should return info with 'scan unavailable'."""
        from secfesc.checks.network.ports import check

        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run",
            return_value=_ss_result("", returncode=-1),
        ):
            result = check()
        assert result["status"] == "info"
        assert "unavailable" in result["value"]

    def test_no_open_ports_returns_ok(self):
        """No listening ports should return ok with 'None'."""
        from secfesc.checks.network.ports import check

        ss_out = "Netid State Recv-Q Send-Q Local Address:Port\n"
        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run", return_value=_ss_result(ss_out)
        ):
            result = check()
        assert result["status"] == "ok"
        assert result["value"] == "None"

    def test_deduplication_ipv4_ipv6(self):
        """Same port on IPv4 and IPv6 should only be counted once."""
        from secfesc.checks.network.ports import check

        ss_out = (
            "Netid State Recv-Q Send-Q Local Address:Port\n"
            "tcp LISTEN 0 128 0.0.0.0:22\n"
            "tcp LISTEN 0 128 [::]:22\n"
        )
        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run", return_value=_ss_result(ss_out)
        ), patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("SSH", "expected")):
            result = check()
        # Exactly one port entry in value
        assert result["value"].count("22") == 1

    def test_ipv6_address_parsed_correctly(self):
        """IPv6 address format [::]:port should parse the port number."""
        from secfesc.checks.network.ports import check

        ss_out = "Netid State Recv-Q Send-Q Local Address:Port\ntcp LISTEN 0 128 [::]:443\n"
        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run", return_value=_ss_result(ss_out)
        ), patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("HTTPS", "expected")):
            result = check()
        assert result["status"] == "ok"
        assert "443" in result["value"]

    def test_unknown_port_gives_warn(self):
        """Port classified as 'unknown' (unregistered registered port) should return warn."""
        from secfesc.checks.network.ports import check

        ss_out = "Netid State Recv-Q Send-Q Local Address:Port\ntcp LISTEN 0 128 0.0.0.0:9999\n"
        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run", return_value=_ss_result(ss_out)
        ), patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("Unknown", "unknown")):
            result = check()
        assert result["status"] == "warn"

    def test_udp_protocol_detected(self):
        """UDP lines should be tagged as UDP in result."""
        from secfesc.checks.network.ports import check

        ss_out = "Netid State Recv-Q Send-Q Local Address:Port\nudp UNCONN 0 0 0.0.0.0:53\n"
        with patch(
            "secfesc.checks.network.ports.safe_subprocess_run", return_value=_ss_result(ss_out)
        ), patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("DNS", "expected")):
            result = check()
        assert "UDP" in result["value"]


class TestServices:
    """Tests for Services check (checks/network/services.py)."""

    def test_suspicious_service_gives_bad(self):
        """A known suspicious service (telnetd) should return bad."""
        from secfesc.checks.network.services import check

        with patch(
            "secfesc.checks.network.services.safe_subprocess_run",
            return_value=_systemctl_result(["sshd", "telnetd"]),
        ):
            result = check()
        assert result["status"] == "bad"
        assert "telnetd" in result["value"]

    def test_unnecessary_service_gives_warn(self):
        """An unnecessary service (cups) should return warn."""
        from secfesc.checks.network.services import check

        with patch(
            "secfesc.checks.network.services.safe_subprocess_run",
            return_value=_systemctl_result(["sshd", "cups"]),
        ):
            result = check()
        assert result["status"] == "warn"
        assert "cups" in result["value"]

    def test_clean_services_gives_ok(self):
        """Only safe services should return ok."""
        from secfesc.checks.network.services import check

        with patch(
            "secfesc.checks.network.services.safe_subprocess_run",
            return_value=_systemctl_result(["sshd", "NetworkManager", "systemd-resolved"]),
        ):
            result = check()
        assert result["status"] == "ok"
        assert "none flagged" in result["value"]

    def test_no_services_gives_none_detected(self):
        """Empty systemctl output should return info."""
        from secfesc.checks.network.services import check

        with patch(
            "secfesc.checks.network.services.safe_subprocess_run",
            return_value=_systemctl_result([]),
        ):
            result = check()
        assert result["status"] == "info"
        assert "None detected" in result["value"]

    def test_systemctl_failure_gives_unavailable(self):
        """systemctl failure should return info."""
        from secfesc.checks.network.services import check

        with patch(
            "secfesc.checks.network.services.safe_subprocess_run",
            return_value=_systemctl_result([], returncode=1),
        ):
            result = check()
        assert result["status"] == "info"
        assert "unavailable" in result["value"]

    def test_case_insensitive_matching(self):
        """Service matching should be case-insensitive (e.g. 'CUPS' matches 'cups')."""
        from secfesc.checks.network.services import check

        # Simulate systemctl returning 'CUPS' in uppercase
        stdout = "CUPS.service  loaded active running CUPS Scheduler\n"
        result_mock = subprocess.CompletedProcess(["systemctl"], 0, stdout, "")
        with patch(
            "secfesc.checks.network.services.safe_subprocess_run", return_value=result_mock
        ):
            result = check()
        assert result["status"] == "warn"

    def test_suspicious_takes_priority_over_unnecessary(self):
        """If both suspicious and unnecessary services exist, result should be bad."""
        from secfesc.checks.network.services import check

        with patch(
            "secfesc.checks.network.services.safe_subprocess_run",
            return_value=_systemctl_result(["cups", "telnetd"]),
        ):
            result = check()
        assert result["status"] == "bad"


class TestFirewallRules:
    """Tests for Firewall Rules check (checks/network/firewall.py)."""

    def _make_result(self, stdout, returncode=0, cmd=None):
        return subprocess.CompletedProcess(cmd or [], returncode, stdout, "")

    def _all_present(self):
        """All three firewall backends visible to shutil.which."""
        return lambda name: f"/usr/sbin/{name}" if name in {"ufw", "nft", "iptables", "firewalld"} else None

    def _only(self, *names):
        """Only the named backends are visible to shutil.which."""
        s = set(names)
        return lambda name: f"/usr/sbin/{name}" if name in s else None

    def test_ufw_active_gives_ok(self):
        """Active ufw with rules should return ok."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["ufw", "status"]:
                return self._make_result("Status: active\n", 0, cmd)
            if cmd == ["ufw", "status", "numbered"]:
                return self._make_result("[1] 22/tcp ALLOW IN  Anywhere\n", 0, cmd)
            return self._make_result("", -1, cmd)

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run), \
             patch("shutil.which", side_effect=self._only("ufw")):
            result = check()
        assert result["status"] == "ok"
        assert "ufw active" in result["value"]

    def test_ufw_inactive_falls_through_to_info_when_no_other_firewall(self):
        """Inactive ufw with no other firewall binary: cannot prove
        absence → info rather than false bad."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["ufw", "status"]:
                return self._make_result("Status: inactive\n", 0, cmd)
            return self._make_result("", -1, cmd)

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run), \
             patch("shutil.which", side_effect=self._only("ufw")):
            result = check()
        assert result["status"] == "info"

    def test_ufw_inactive_falls_through_to_nftables(self):
        """Inactive ufw should fall through to nftables if it has rules."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["ufw", "status"]:
                return self._make_result("Status: inactive\n", 0, cmd)
            if cmd == ["nft", "list", "ruleset"]:
                return self._make_result("table inet filter { chain input { } }\n", 0, cmd)
            return self._make_result("", -1, cmd)

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run), \
             patch("shutil.which", side_effect=self._only("ufw", "nft")):
            result = check()
        assert result["status"] == "ok"
        assert "nftables" in result["value"]

    def test_ufw_unavailable_falls_through_to_nft(self):
        """If ufw is unavailable, should fall through to nftables."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["nft", "list", "ruleset"]:
                return self._make_result("table inet filter {\n  chain input { }\n}\n", 0, cmd)
            return self._make_result("", -1, cmd)

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run), \
             patch("shutil.which", side_effect=self._only("nft")):
            result = check()
        assert result["status"] == "ok"
        assert "nftables" in result["value"]

    def test_nft_unavailable_falls_through_to_iptables(self):
        """If ufw and nft unavailable, should fall through to iptables."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["iptables", "-L", "-n"]:
                return self._make_result("ACCEPT all -- 0.0.0.0/0\nDROP all\n", 0, cmd)
            return self._make_result("", -1, cmd)

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run), \
             patch("shutil.which", side_effect=self._only("iptables")):
            result = check()
        assert result["status"] == "ok"
        assert "iptables" in result["value"]

    def test_no_firewall_gives_info(self):
        """When no firewall binary can be probed, info (not bad)."""
        from secfesc.checks.network.firewall import check

        with patch(
            "secfesc.checks.network.firewall.safe_subprocess_run",
            return_value=self._make_result("", -1),
        ), patch("shutil.which", return_value=None):
            result = check()
        assert result["status"] == "info"
        assert "unreadable" in result["value"]

    def test_nftables_present_but_empty_gives_bad(self):
        """If nft is present but ruleset is empty, we have evidence of no
        active firewall → bad."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["nft", "list", "ruleset"]:
                return self._make_result("# empty ruleset\n", 0, cmd)
            return self._make_result("", -1, cmd)

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run), \
             patch("shutil.which", side_effect=self._only("nft")):
            result = check()
        assert result["status"] == "bad"
        assert "no rules" in result["value"]

    def test_ufw_rules_count_in_value(self):
        """Rule count should appear in the result value."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["ufw", "status"]:
                return self._make_result("Status: active\n", 0, cmd)
            if cmd == ["ufw", "status", "numbered"]:
                return self._make_result(
                    "[1] 22/tcp ALLOW\n[2] 80/tcp ALLOW\n[3] 443/tcp ALLOW\n", 0, cmd
                )
            return self._make_result("", -1, cmd)

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run), \
             patch("shutil.which", side_effect=self._only("ufw")):
            result = check()
        assert "3" in result["value"]


class TestParsePortsEdgeCases:
    """Edge cases for _parse_ports() in ports.py."""

    def _run(self, stdout):
        from secfesc.checks.network.ports import _parse_ports

        with patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("unknown", "info")):
            return _parse_ports(stdout)

    def test_ipv6_scope_id_parsed_correctly(self):
        """IPv6 address with scope ID like [fe80::1%eth0]:22 should parse port 22."""
        result = self._run(
            "Netid State Recv-Q Send-Q Local Address:Port\n"
            "tcp   LISTEN 0      128    [fe80::1%eth0]:22\n"
        )
        assert any(p["port"] == "22" for p in result)

    def test_malformed_line_without_port_is_skipped(self):
        """Lines without a parseable port number should be silently skipped."""
        result = self._run(
            "Netid State Recv-Q Send-Q Local Address:Port\n"
            "tcp   LISTEN 0      128    invalid-no-port\n"
        )
        assert result == []

    def test_out_of_range_port_is_skipped(self):
        """Port numbers outside 0-65535 should be skipped."""
        result = self._run(
            "Netid State Recv-Q Send-Q Local Address:Port\n"
            "tcp   LISTEN 0      128    0.0.0.0:99999\n"
        )
        assert result == []

    def test_corrupt_ss_output_does_not_crash(self):
        """Completely malformed ss output should return empty list without exception."""
        result = self._run("GARBAGE\x00DATA\nNot a real line\n")
        assert isinstance(result, list)

    def test_port_extracted_but_not_numeric_is_skipped(self):
        """If regex matches but captured group is not numeric, skip the port."""
        # Craft a line where _PORT_RE finds a match but the captured group is not a number.
        # _PORT_RE = r"(?:\[.*\]|[^:]+):(\d+)$" — \d+ ensures it's numeric, so
        # the ValueError branch is hit by returning non-numeric after a forced match.
        from unittest.mock import patch

        from secfesc.checks.network.ports import _parse_ports

        mock_re = type("M", (), {"group": lambda self, n: "abc"})()

        with patch("secfesc.checks.network.ports._PORT_RE") as fake_re:
            fake_re.search.return_value = mock_re
            with patch("secfesc.secfetch.data.port_db.get_port_info", return_value=("x", "info")):
                result = _parse_ports(
                    "Netid State Recv-Q Send-Q Local Address:Port\n"
                    "tcp   LISTEN 0      128    0.0.0.0:22\n"
                )
        assert result == []

    def test_short_mode_colorizes_port_only(self):
        """When SECFETCH_SHORT=1, format_port omits name/proto."""
        import os

        from secfesc.checks.network.ports import check

        ss_out = "Netid State Recv-Q Send-Q Local Address:Port\ntcp LISTEN 0 128 0.0.0.0:22\n"
        with patch("secfesc.checks.network.ports.safe_subprocess_run",
                   return_value=_ss_result(ss_out)), \
             patch("secfesc.secfetch.data.port_db.get_port_info",
                   return_value=("SSH", "expected")):
            os.environ["SECFETCH_SHORT"] = "1"
            try:
                result = check()
            finally:
                os.environ["SECFETCH_SHORT"] = "0"
        assert result["status"] == "ok"
        assert "22" in result["value"]

    def test_ufw_active_numbered_command_fails(self):
        """Active ufw where numbered command fails still reports ok with 0 rules."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["ufw", "status"]:
                return _firewall_result("Status: active\n")
            return _firewall_result("", returncode=1)

        def only_ufw(name):
            return "/usr/sbin/ufw" if name == "ufw" else None

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run), \
             patch("shutil.which", side_effect=only_ufw):
            result = check()
        assert result["status"] == "ok"
        assert "ufw active" in result["value"]
        assert "0 rules" in result["value"]

    def test_firewalld_active_gives_ok(self):
        """Active firewalld (via systemctl) returns ok immediately."""
        from secfesc.checks.network.firewall import check

        def mock_run(cmd, **kwargs):
            if cmd == ["systemctl", "is-active", "firewalld"]:
                return _firewall_result("active\n", returncode=0)
            return _firewall_result("", returncode=1)

        with patch("secfesc.checks.network.firewall.safe_subprocess_run", side_effect=mock_run):
            result = check()
        assert result["status"] == "ok"
        assert "firewalld" in result["value"]
