import os


def load_config():
    return os.getenv("APP_REGION", "local")
