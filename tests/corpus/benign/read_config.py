from pathlib import Path


def read_config(path="config.json"):
    return Path(path).read_text(encoding="utf-8")

