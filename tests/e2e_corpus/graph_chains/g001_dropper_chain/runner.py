import subprocess

from writer import write_stage


def run_stage(url):
    payload_path = write_stage(url, "/tmp/stage_payload.py")
    subprocess.run(["python", payload_path], check=False)
