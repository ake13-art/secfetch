from secfetch.core.registry import register


def security_check(name, category, risk="info"):
    def wrapper(func):
        # build check dict and register it immediately on import
        register({"name": name, "category": category, "risk": risk, "run": func})
        return func

    return wrapper
