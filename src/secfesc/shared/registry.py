"""Shared check framework: the @security_check decorator plus the registry,
discovery loader and parallel runner.

Both tools consume this single framework: secfetch renders the results
compactly, secscan renders them as a deep audit. Adding one check therefore
serves both tools.
"""
from __future__ import annotations

import importlib
import pkgutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import secfesc.checks
from secfesc.shared.config import is_enabled, load_config
from secfesc.shared.logger import log_debug, log_error
from secfesc.shared.types import CheckRegistration, CheckResult

# ── Registry ──────────────────────────────────
_checks: list[CheckRegistration] = []
_discovered = False
_discover_lock = threading.Lock()
_registry_lock = threading.Lock()

VALID_RISKS = frozenset({"high", "medium", "low", "info"})
VALID_CATEGORIES = frozenset({
    "system",
    "kernel_security",
    "kernel_hardening",
    "network",
    "filesystem",
})


def register(check: CheckRegistration) -> None:
    """Add a check dict to the global registry. Called by the @security_check decorator."""
    if check["risk"] not in VALID_RISKS:
        raise ValueError(
            f"Invalid risk {check['risk']!r} for {check['name']!r}; "
            f"expected one of {sorted(VALID_RISKS)}"
        )
    if check["category"] not in VALID_CATEGORIES:
        log_error(
            f"Unknown category {check['category']!r} for {check['name']!r}; "
            f"expected one of {sorted(VALID_CATEGORIES)}"
        )
    with _registry_lock:
        _checks.append(check)


def get_checks() -> list[CheckRegistration]:
    with _registry_lock:
        return list(_checks)


# ── Decorator ─────────────────────────────────
def security_check(
    name: str, category: str, risk: str = "info"
) -> Callable[[Callable[[], CheckResult]], Callable[[], CheckResult]]:
    """Register a check function in the global registry.

    The wrapped function is returned unchanged so it stays directly testable.
    """

    def wrapper(func: Callable[[], CheckResult]) -> Callable[[], CheckResult]:
        register({"name": name, "category": category, "risk": risk, "run": func})
        return func

    return wrapper


# ── Loader ────────────────────────────────────
def _discover_checks() -> None:
    """Auto-import all check modules so decorators fire.

    Thread-safe: Sets _discovered only after successful loading.
    """
    global _discovered
    with _discover_lock:
        if _discovered:
            return
        # Note: _discovered remains False during loading to allow retry on failure

        failed = 0
        for mod in pkgutil.walk_packages(
            secfesc.checks.__path__,
            secfesc.checks.__name__ + ".",
        ):
            try:
                importlib.import_module(mod.name)
            except (ImportError, ModuleNotFoundError, SyntaxError) as e:
                failed += 1
                log_error(f"Failed to load security check module {mod.name}: {e}")

        # Set flag even on partial failure so we don't repeatedly retry
        _discovered = True
        if failed:
            log_error(f"Check discovery completed with {failed} module(s) failed")


# ── Runner ────────────────────────────────────
def _run_single(check: CheckRegistration) -> CheckResult:
    """Execute one check and return a fully-populated result dict."""
    try:
        raw = check["run"]()
        if (
            not isinstance(raw, dict)
            or "status" not in raw
            or "value" not in raw
            or not isinstance(raw["status"], str)
            or not isinstance(raw["value"], str)
            or raw["status"] not in {"ok", "warn", "bad", "info"}
        ):
            log_debug(f"Check {check['name']!r} returned an invalid result: {raw!r}")
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
        # Log details internally; never expose exception text to the user —
        # it can contain absolute paths or file content snippets.
        log_debug(f"Check {check['name']!r} raised: {type(e).__name__}: {e}")
        return {
            "name": check["name"],
            "category": check["category"],
            "risk": check["risk"],
            "status": "info",
            "value": "check unavailable",
        }


def run_checks(fast: bool = False) -> list[CheckResult]:
    config = load_config()
    _discover_checks()

    active = [
        c
        for c in _checks
        if not fast or is_enabled(config, c["name"].lower().replace(" ", "_"))
    ]

    if not active:
        return []
    results: list[CheckResult | None] = [None] * len(active)
    max_workers = min(len(active), 8)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_run_single, c): i for i, c in enumerate(active)}
        for future in as_completed(futures):
            idx = futures[future]
            results[idx] = future.result()
    return [r for r in results if r is not None]
