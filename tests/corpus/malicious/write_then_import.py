import importlib


def write_and_import():
    with open("stage_two.py", "w", encoding="utf-8") as handle:
        handle.write("print('loaded')")
    return importlib.import_module("stage_two")

