from __future__ import annotations

from typing import Callable

from secfetch.core.engine import register
from secfetch.core.types import CheckResult


def security_check(
    name: str, category: str, risk: str = "info"
) -> Callable[[Callable[[], CheckResult]], Callable[[], CheckResult]]:
    def wrapper(func: Callable[[], CheckResult]) -> Callable[[], CheckResult]:
        register({"name": name, "category": category, "risk": risk, "run": func})
        return func

    return wrapper
