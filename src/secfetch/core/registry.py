_checks = []


def register(check):
    _checks.append(check)


def get_checks():
    return list(_checks)
