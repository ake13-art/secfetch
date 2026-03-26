import os
import csv
import threading
import urllib.request
from datetime import datetime
from pathlib import Path

# Cache location
CACHE_DIR = Path.home() / ".cache" / "secfetch"
CACHE_FILE = CACHE_DIR / "port_db.csv"
IANA_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

# Minimal fallback DB if no cache and no network
FALLBACK_PORTS = {
    20: ("FTP Data", "unnecessary"),
    21: ("FTP", "unnecessary"),
    22: ("SSH", "expected"),
    23: ("Telnet", "suspicious"),
    25: ("SMTP", "expected"),
    53: ("DNS", "expected"),
    67: ("DHCP Server", "expected"),
    68: ("DHCP Client", "expected"),
    80: ("HTTP", "expected"),
    110: ("POP3", "unnecessary"),
    143: ("IMAP", "unnecessary"),
    443: ("HTTPS", "expected"),
    445: ("SMB", "suspicious"),
    3389: ("RDP", "suspicious"),
}

# In-memory port DB: {port: (service_name, protocol)}
_port_db: dict[int, tuple[str, str]] = {}


def _has_network() -> bool:
    # Quick check via HEAD request to IANA
    try:
        urllib.request.urlopen(IANA_URL, timeout=2)
        return True
    except:
        return False


def _get_remote_last_modified() -> str | None:
    # HTTP HEAD to check if remote CSV is newer
    try:
        req = urllib.request.Request(IANA_URL, method="HEAD")
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.headers.get("Last-Modified")
    except:
        return None


def _get_local_last_modified() -> str | None:
    # Read timestamp stored alongside cache
    ts_file = CACHE_FILE.with_suffix(".timestamp")
    if ts_file.exists():
        return ts_file.read_text().strip()
    return None


def _download_csv():
    # Download fresh CSV and save to cache
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(IANA_URL)
        with urllib.request.urlopen(req, timeout=10) as r:
            data = r.read().decode("utf-8")
            last_modified = r.headers.get("Last-Modified", "")
        CACHE_FILE.write_text(data, encoding="utf-8")
        CACHE_FILE.with_suffix(".timestamp").write_text(last_modified)
        _parse_csv(data)
    except Exception as e:
        pass  # Silent fail, fallback still active


def _parse_csv(data: str):
    # Parse IANA CSV into _port_db
    # Columns: Service Name, Port Number, Transport Protocol, Description, ...
    global _port_db
    reader = csv.reader(data.splitlines())
    next(reader, None)  # skip header
    for row in reader:
        if len(row) < 3:
            continue
        service, port_str, proto = row[0], row[1], row[2]
        if not port_str.isdigit():
            continue  # skip ranges and empty
        port = int(port_str)
        if service:
            _port_db[port] = (service, proto.upper() if proto else "TCP/UDP")


def _check_and_update():
    # Background thread: compare timestamps, download if outdated
    remote = _get_remote_last_modified()
    local = _get_local_last_modified()
    if remote and remote != local:
        _download_csv()


def _load_cache():
    # Load existing cache from disk
    if CACHE_FILE.exists():
        _parse_csv(CACHE_FILE.read_text(encoding="utf-8"))
        return True
    return False


def initialize():
    # Called once at secfetch startup
    loaded = _load_cache()

    if not loaded:
        # No cache: try to download immediately (first run)
        if _has_network():
            _download_csv()
        else:
            # No cache, no network: use fallback
            for port, (name, status) in FALLBACK_PORTS.items():
                _port_db[port] = (name, "TCP")
    else:
        # Cache exists: check for updates silently in background
        threading.Thread(target=_check_and_update, daemon=True).start()


def get_port_info(port: int, proto: str = "TCP") -> tuple[str, str]:
    # Returns (service_name, risk_level)
    # risk_level: expected / unnecessary / suspicious / unknown
    if port in _port_db:
        name, _ = _port_db[port]
        # Check fallback for known risk levels
        if port in FALLBACK_PORTS:
            return (name, FALLBACK_PORTS[port][1])
        return (name, _classify(port))
    # Unknown port logic
    if port < 1024:
        return ("Unknown", "suspicious")
    if port < 49152:
        return ("Unknown", "warn")
    return ("Dynamic/Ephemeral", "info")


def _classify(port: int) -> str:
    # Default classification for ports not in fallback
    if port in (80, 443, 22, 25, 53, 67, 68):
        return "expected"
    if port < 1024:
        return "unnecessary"
    return "unknown"
