import requests


def fetch_public_status():
    return requests.get("https://status.example/api", timeout=5).json()
