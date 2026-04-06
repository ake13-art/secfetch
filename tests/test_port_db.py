"""Tests for port database module."""
import threading

from secfetch.data import port_db


class TestParseCSV:
    """Tests for CSV parsing."""

    def test_parse_basic_csv(self):
        csv_data = "Service Name,Port Number,Transport Protocol\nssh,22,tcp\nhttp,80,tcp\n"
        port_db._parse_csv(csv_data)
        assert 22 in port_db._port_db
        assert port_db._port_db[22] == ("ssh", "TCP")
        assert 80 in port_db._port_db

    def test_parse_skips_non_numeric_ports(self):
        csv_data = "Service Name,Port Number,Transport Protocol\nssh,22,tcp\nbad,abc,tcp\n"
        port_db._parse_csv(csv_data)
        assert 22 in port_db._port_db

    def test_parse_skips_short_rows(self):
        csv_data = "Service Name,Port Number,Transport Protocol\nssh,22,tcp\nshort,22\n"
        port_db._parse_csv(csv_data)
        assert 22 in port_db._port_db

    def test_parse_empty_proto_defaults(self):
        csv_data = "Service Name,Port Number,Transport Protocol\nssh,22,\n"
        port_db._parse_csv(csv_data)
        assert port_db._port_db[22] == ("ssh", "TCP/UDP")


class TestGetPortInfo:
    """Tests for port info lookup."""

    def test_known_fallback_port(self):
        port_db._port_db = {22: ("ssh", "TCP")}
        name, risk = port_db.get_port_info(22)
        assert name == "ssh"
        assert risk == "expected"

    def test_unknown_low_port(self):
        port_db._port_db = {}
        name, risk = port_db.get_port_info(999)
        assert risk == "suspicious"

    def test_unknown_registered_port(self):
        port_db._port_db = {}
        name, risk = port_db.get_port_info(8080)
        assert risk == "unknown"

    def test_ephemeral_port(self):
        port_db._port_db = {}
        name, risk = port_db.get_port_info(50000)
        assert risk == "info"


class TestThreadSafety:
    """Tests for thread-safe port database access."""

    def test_concurrent_read_write(self):
        """get_port_info should not crash during concurrent _parse_csv updates."""
        errors = []

        def reader():
            for _ in range(100):
                try:
                    port_db.get_port_info(22)
                except Exception as e:
                    errors.append(e)

        def writer():
            csv_data = "Service Name,Port Number,Transport Protocol\nssh,22,tcp\n"
            for _ in range(100):
                try:
                    port_db._parse_csv(csv_data)
                except Exception as e:
                    errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety errors: {errors}"
