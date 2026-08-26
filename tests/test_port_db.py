"""Tests for port database module."""
import threading
import urllib.request
from unittest.mock import MagicMock

from secfesc.secfetch.data import port_db


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
        assert risk == "expected"


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


class TestGetPortInfoClassify:
    """Cover the _classify path and fallback logic."""

    def test_port_in_db_not_in_fallback_uses_classify(self):
        port_db._port_db = {9999: ("some-service", "TCP")}
        name, risk = port_db.get_port_info(9999)
        assert name == "some-service"
        assert risk == "unknown"  # >= 1024, not in fallback

    def test_classify_low_port_is_suspicious(self):
        assert port_db._classify(80) == "suspicious"

    def test_classify_high_port_is_unknown(self):
        assert port_db._classify(8080) == "unknown"

    def test_fallback_only_port(self):
        # Port in FALLBACK_PORTS but not in _port_db
        port_db._port_db = {}
        name, risk = port_db.get_port_info(23)  # Telnet
        assert risk == "suspicious"


class TestLoadCache:
    def test_returns_false_when_no_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(port_db, "CACHE_FILE", tmp_path / "port_db.csv")
        assert port_db._load_cache() is False

    def test_returns_true_and_parses_when_cache_exists(self, tmp_path, monkeypatch):
        cache = tmp_path / "port_db.csv"
        cache.write_text("Service Name,Port Number,Transport Protocol\nhttps,443,tcp\n")
        monkeypatch.setattr(port_db, "CACHE_FILE", cache)
        result = port_db._load_cache()
        assert result is True
        assert 443 in port_db._port_db


class TestGetLocalLastModified:
    def test_returns_none_when_no_timestamp_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(port_db, "CACHE_FILE", tmp_path / "port_db.csv")
        assert port_db._get_local_last_modified() is None

    def test_returns_content_when_file_exists(self, tmp_path, monkeypatch):
        cache = tmp_path / "port_db.csv"
        ts = tmp_path / "port_db.timestamp"
        ts.write_text("Thu, 01 Jan 2026 00:00:00 GMT")
        monkeypatch.setattr(port_db, "CACHE_FILE", cache)
        assert port_db._get_local_last_modified() == "Thu, 01 Jan 2026 00:00:00 GMT"


class TestGetRemoteLastModified:
    def test_returns_none_on_network_error(self, monkeypatch):
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda *a, **kw: (_ for _ in ()).throw(OSError("no network")))
        assert port_db._get_remote_last_modified() is None

    def test_returns_header_value(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.headers.get.return_value = "Wed, 01 Jan 2025 00:00:00 GMT"
        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: mock_resp)
        result = port_db._get_remote_last_modified()
        assert result == "Wed, 01 Jan 2025 00:00:00 GMT"


class TestCheckAndUpdate:
    def test_downloads_if_timestamps_differ(self, monkeypatch):
        downloaded = []
        monkeypatch.setattr(port_db, "_get_remote_last_modified", lambda: "new")
        monkeypatch.setattr(port_db, "_get_local_last_modified", lambda: "old")
        monkeypatch.setattr(port_db, "_download_csv", lambda: downloaded.append(1))
        port_db._check_and_update()
        assert downloaded

    def test_skips_download_when_timestamps_match(self, monkeypatch):
        downloaded = []
        monkeypatch.setattr(port_db, "_get_remote_last_modified", lambda: "same")
        monkeypatch.setattr(port_db, "_get_local_last_modified", lambda: "same")
        monkeypatch.setattr(port_db, "_download_csv", lambda: downloaded.append(1))
        port_db._check_and_update()
        assert not downloaded

    def test_skips_download_when_remote_unavailable(self, monkeypatch):
        downloaded = []
        monkeypatch.setattr(port_db, "_get_remote_last_modified", lambda: None)
        monkeypatch.setattr(port_db, "_get_local_last_modified", lambda: "some")
        monkeypatch.setattr(port_db, "_download_csv", lambda: downloaded.append(1))
        port_db._check_and_update()
        assert not downloaded


class TestDownloadCSV:
    def test_writes_cache_atomically(self, tmp_path, monkeypatch):
        cache = tmp_path / "port_db.csv"
        monkeypatch.setattr(port_db, "CACHE_FILE", cache)
        monkeypatch.setattr(port_db, "CACHE_DIR", tmp_path)
        csv_data = "Service Name,Port Number,Transport Protocol\nhttps,443,tcp\n"
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = csv_data.encode()
        mock_resp.headers.get.return_value = "Thu, 01 Jan 2026 00:00:00 GMT"
        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: mock_resp)
        port_db._download_csv()
        assert cache.exists()
        assert "https" in cache.read_text()

    def test_logs_error_on_network_failure(self, tmp_path, monkeypatch):
        monkeypatch.setattr(port_db, "CACHE_FILE", tmp_path / "port_db.csv")
        monkeypatch.setattr(port_db, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda *a, **kw: (_ for _ in ()).throw(OSError("no network")))
        errors = []
        monkeypatch.setattr("secfesc.secfetch.data.port_db.log_error", lambda msg: errors.append(msg))
        port_db._download_csv()
        assert errors


class TestInitialize:
    def test_uses_cache_if_present(self, tmp_path, monkeypatch):
        cache = tmp_path / "port_db.csv"
        cache.write_text("Service Name,Port Number,Transport Protocol\nssh,22,tcp\n")
        monkeypatch.setattr(port_db, "CACHE_FILE", cache)
        monkeypatch.setattr(port_db, "_check_and_update", lambda: None)
        port_db._port_db = {}
        port_db.initialize()
        assert 22 in port_db._port_db

    def test_uses_fallback_when_no_cache_no_network(self, tmp_path, monkeypatch):
        monkeypatch.setattr(port_db, "CACHE_FILE", tmp_path / "port_db.csv")
        # Stub the download so the background thread is a no-op.
        monkeypatch.setattr(port_db, "_download_csv", lambda: None)
        port_db._port_db = {}
        # The fallback is loaded synchronously before the background download
        # is spawned — we can read it immediately, no need to wait on the thread.
        port_db.initialize()
        assert 22 in port_db._port_db

    def test_spawns_background_update_when_cache_exists(self, tmp_path, monkeypatch):
        cache = tmp_path / "port_db.csv"
        cache.write_text("Service Name,Port Number,Transport Protocol\nssh,22,tcp\n")
        monkeypatch.setattr(port_db, "CACHE_FILE", cache)
        # Throttle must NOT block — pretend we never checked before.
        monkeypatch.setattr(port_db, "_check_throttled", lambda: False)
        called = []
        monkeypatch.setattr(port_db, "_check_and_update", lambda: called.append(1))
        port_db._port_db = {}
        port_db.initialize()
        import time
        time.sleep(0.1)  # allow daemon thread to run
        assert called
