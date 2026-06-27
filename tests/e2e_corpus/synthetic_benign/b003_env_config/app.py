import os


def load_config():
    return {
        "region": os.getenv("APP_REGION", "local"),
        "debug": os.getenv("APP_DEBUG", "0") == "1",
    }
