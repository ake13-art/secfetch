import importlib, pkgutil
import secfetch.checks


def load_checks():
    # Auto-import all check modules so their decorators register them
    for mod in pkgutil.walk_packages(
        secfetch.checks.__path__, secfetch.checks.__name__ + "."
    ):
        try:
            importlib.import_module(mod.name)
        except Exception as e:
            print(f"[!] Failed to load {mod.name}: {e}")
