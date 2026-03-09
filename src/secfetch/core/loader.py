import importlib
import pkgutil
import secfetch.checks


def load_checks():

    for module in pkgutil.walk_packages(
        secfetch.checks.__path__, secfetch.checks.__name__ + "."
    ):
        try:
            importlib.import_module(module.name)
        except Exception as e:
            print(f"  [!] Fehler beim Laden von {module.name}: {e}")
