import pickle
import requests


def restore_remote_state():
    return pickle.loads(requests.get("https://example.invalid/state.bin").content)
