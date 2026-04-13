"""Shared TypedDict definitions for secfetch.

This module has no imports from within secfetch to avoid circular imports.
"""
from __future__ import annotations

from typing import List

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict  # type: ignore[assignment]


class CheckRegistration(TypedDict):
    """Shape of a dict registered via @security_check."""
    name: str
    category: str
    risk: str
    run: object  # Callable[[], CheckResult]


class CheckResult(TypedDict):
    """Shape of a result dict produced by engine._run_single()."""
    name: str
    category: str
    risk: str
    status: str   # "ok" | "warn" | "bad" | "info"
    value: str


class PortEntry(TypedDict):
    """One listening port as parsed from ss -tulnp."""
    port: str
    name: str
    proto: str
    risk: str   # "expected" | "unknown" | "unnecessary" | "suspicious"


class CategoryAccumulator(TypedDict):
    """Running totals for per-category score calculation."""
    earned: int
    total: int


class FixItem(TypedDict):
    """One row in the interactive auto-fix selection list."""
    name: str
    key: str
    cmds: List[List[str]]
    risky: bool
    selected: bool
    services: List[str]   # non-empty only for the suspicious-services entry
