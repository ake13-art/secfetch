from secfetch.core.engine import register


def security_check(name, category, risk="info"):
    # Decorator: registers a check function on import
    def wrapper(func):
        register({"name": name, "category": category, "risk": risk, "run": func})
        return func

    return wrapper
