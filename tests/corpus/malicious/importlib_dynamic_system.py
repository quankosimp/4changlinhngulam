import importlib


def dynamic_command():
    module = importlib.import_module("os")
    module.system("id")

