"""Central engine: discovers, registers and runs all checks."""
from __future__ import annotations

import importlib
import pkgutil
import threading

import secfetch.checks
from secfetch.core.config import is_enabled, load_config
from secfetch.core.logger import log_error

# ── Registry ──────────────────────────────────
_checks: list[dict] = []
_discovered = False
_discover_lock = threading.Lock()


def register(check: dict):
    _checks.append(check)


def get_checks() -> list[dict]:
    return list(_checks)


# ── Loader ────────────────────────────────────
def _discover_checks():
    """Auto-import all check modules so decorators fire."""
    global _discovered
    with _discover_lock:
        if _discovered:
            return
        _discovered = True

    for mod in pkgutil.walk_packages(
        secfetch.checks.__path__,
        secfetch.checks.__name__ + ".",
    ):
        try:
            importlib.import_module(mod.name)
        except Exception as e:
            log_error(f"Failed to load security check module {mod.name}: {e}")


# ── Runner ────────────────────────────────────
def run_checks(fast: bool = False) -> list[dict]:
    config = load_config()
    _discover_checks()

    results = []
    for check in _checks:
        key = check["name"].lower().replace(" ", "_")
        if fast and not is_enabled(config, key):
            continue
        try:
            raw = check["run"]()
            if not isinstance(raw, dict) or "status" not in raw or "value" not in raw:
                raw = {"status": "info", "value": "invalid check result"}
            raw.update(
                {
                    "name": check["name"],
                    "category": check["category"],
                    "risk": check["risk"],
                }
            )
            results.append(raw)
        except Exception as e:
            results.append(
                {
                    "name": check["name"],
                    "category": check["category"],
                    "risk": check["risk"],
                    "status": "info",
                    "value": f"Error: {e}",
                }
            )
    return results
