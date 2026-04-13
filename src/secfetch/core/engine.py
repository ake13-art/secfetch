"""Central engine: discovers, registers and runs all checks."""

from __future__ import annotations

import importlib
import pkgutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import secfetch.checks
from secfetch.core.config import is_enabled, load_config
from secfetch.core.logger import log_error
from secfetch.core.types import CheckRegistration, CheckResult

# ── Registry ──────────────────────────────────
_checks: list[CheckRegistration] = []
_discovered = False
_discover_lock = threading.Lock()
_registry_lock = threading.Lock()


def register(check: CheckRegistration) -> None:
    """Add a check dict to the global registry. Called by the @security_check decorator."""
    with _registry_lock:
        _checks.append(check)


def get_checks() -> list[CheckRegistration]:
    with _registry_lock:
        return list(_checks)


# ── Loader ────────────────────────────────────
def _discover_checks() -> None:
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
def _run_single(check: CheckRegistration) -> CheckResult:
    """Execute one check and return a fully-populated result dict."""
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
        return raw
    except Exception as e:
        return {
            "name": check["name"],
            "category": check["category"],
            "risk": check["risk"],
            "status": "info",
            "value": f"Error: {e}",
        }


def run_checks(fast: bool = False) -> list[CheckResult]:
    config = load_config()
    _discover_checks()

    active = [
        c
        for c in _checks
        if not (fast and not is_enabled(config, c["name"].lower().replace(" ", "_")))
    ]

    results: list[CheckResult | None] = [None] * len(active)
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_run_single, c): i for i, c in enumerate(active)}
        for future in as_completed(futures):
            idx = futures[future]
            results[idx] = future.result()
    return [r for r in results if r is not None]
