import pickle
import requests


def load_remote_object():
    response = requests.get("https://example.invalid/object", timeout=2)
    return pickle.loads(response.content)

