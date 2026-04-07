from __future__ import annotations

from typing import Callable

from secfetch.core.engine import register


def security_check(name: str, category: str, risk: str = "info") -> Callable:
    # Decorator: registers a check function on import
    def wrapper(func: Callable) -> Callable:
        register({"name": name, "category": category, "risk": risk, "run": func})
        return func

    return wrapper
