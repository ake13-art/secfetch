from pathlib import Path


def read_file(path):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return None
