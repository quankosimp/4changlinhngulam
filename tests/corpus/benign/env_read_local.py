import os


def get_setting():
    return os.environ.get("APP_MODE", "dev")

