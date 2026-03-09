from secfetch.core.registry import register


def security_check(name, category, risk="info"):

    def wrapper(func):

        # create check object
        check = {"name": name, "category": category, "risk": risk, "run": func}

        # automatic registration
        register(check)

        return func

    return wrapper
