import importlib

from builder import write_plugin


def load_plugin():
    module_path = write_plugin("/tmp/generated_plugin.py")
    module_name = module_path.rsplit("/", 1)[-1].removesuffix(".py")
    return importlib.import_module(module_name)
