import requests


def fetch_status():
    response = requests.get("https://example.invalid/status", timeout=2)
    return response.json()

