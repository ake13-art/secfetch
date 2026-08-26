from __future__ import annotations

import csv
import os
import threading
import time
import urllib.request
from pathlib import Path

from secfesc.shared.logger import log_error

# Cache location
CACHE_DIR = Path.home() / ".cache" / "secfetch"
CACHE_FILE = CACHE_DIR / "port_db.csv"
LAST_CHECK_FILE = CACHE_DIR / "last_check"
# Minimum interval between remote update checks (per process).
_UPDATE_CHECK_INTERVAL = 24 * 60 * 60  # 24 hours
IANA_URL = (
    "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
)

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
_lock = threading.Lock()


def _get_remote_last_modified() -> str | None:
    # HTTP HEAD to check if remote CSV is newer
    try:
        req = urllib.request.Request(IANA_URL, method="HEAD")
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.headers.get("Last-Modified")
    except Exception:
        return None


def _get_local_last_modified() -> str | None:
    # Read timestamp stored alongside cache
    ts_file = CACHE_FILE.with_suffix(".timestamp")
    if ts_file.exists():
        return ts_file.read_text().strip()
    return None


def _download_csv() -> None:
    # Download fresh CSV and save to cache atomically (temp file → rename)
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(IANA_URL)
        with urllib.request.urlopen(req, timeout=10) as r:
            data = r.read().decode("utf-8")
            last_modified = r.headers.get("Last-Modified", "")
        _atomic_write(CACHE_FILE, data)
        _atomic_write(CACHE_FILE.with_suffix(".timestamp"), last_modified)
        _parse_csv(data)
    except Exception as e:
        log_error(f"Failed to download port database: {e}")


def _atomic_write(target: Path, data: str) -> None:
    """Write *data* to *target* atomically with mode 0o600."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    # If a previous run was killed mid-write, the .tmp may still be there.
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def _parse_csv(data: str) -> None:
    # Parse IANA CSV into _port_db
    # Columns: Service Name, Port Number, Transport Protocol, Description, ...
    global _port_db
    new_db: dict[int, tuple[str, str]] = {}
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
            new_db[port] = (service, proto.upper() if proto and proto.strip() else "TCP/UDP")
    with _lock:
        _port_db = new_db


def _check_and_update() -> None:
    # Background thread: compare timestamps, download if outdated
    _mark_checked()
    remote = _get_remote_last_modified()
    local = _get_local_last_modified()
    if remote and remote != local:
        _download_csv()


def _last_check_age() -> float | None:
    """Seconds since the last update check, or None if never checked."""
    try:
        mtime = LAST_CHECK_FILE.stat().st_mtime
    except OSError:
        return None
    return time.time() - mtime


def _mark_checked() -> None:
    try:
        LAST_CHECK_FILE.parent.mkdir(parents=True, exist_ok=True)
        LAST_CHECK_FILE.touch()
    except OSError as e:
        log_error(f"Could not record port_db check timestamp: {e}")


def _check_throttled() -> bool:
    """Return True if a remote check should be skipped due to throttling."""
    age = _last_check_age()
    if age is None:
        return False
    return age < _UPDATE_CHECK_INTERVAL


def _load_cache() -> bool:
    # Load existing cache from disk
    if CACHE_FILE.exists():
        _parse_csv(CACHE_FILE.read_text(encoding="utf-8"))
        return True
    return False


def initialize() -> None:
    # Called once at secfetch startup
    loaded = _load_cache()

    if not loaded:
        # No cache: use fallback immediately, download in background.
        # Atomic dict swap under the lock so concurrent readers see either
        # the old (possibly empty) dict or the new fallback, never a
        # half-built one.
        global _port_db
        with _lock:
            _port_db = dict(FALLBACK_PORTS)
        threading.Thread(target=_download_csv, daemon=True).start()
    elif _check_throttled():
        # Cache exists and we checked the remote recently: do nothing.
        return
    else:
        # Cache exists: check for updates silently in background
        threading.Thread(target=_check_and_update, daemon=True).start()


def get_port_info(port: int) -> tuple[str, str]:
    # Returns (service_name, risk_level)
    # risk_level: expected / unnecessary / suspicious / unknown
    with _lock:
        db = dict(_port_db)
    if port in db:
        name, _ = db[port]
        # Check fallback for known risk levels
        if port in FALLBACK_PORTS:
            return (name, FALLBACK_PORTS[port][1])
        return (name, _classify(port))
    # Check fallback for ports not in the downloaded DB
    if port in FALLBACK_PORTS:
        return FALLBACK_PORTS[port]
    # Unknown port logic
    if port < 1024:
        return ("Unknown", "suspicious")
    if port < 49152:
        return ("Unknown", "unknown")
    return ("Dynamic/Ephemeral", "expected")


def _classify(port: int) -> str:
    # Default classification for ports in the IANA DB but not in FALLBACK_PORTS.
    if port < 1024:
        return "suspicious"
    return "unknown"
