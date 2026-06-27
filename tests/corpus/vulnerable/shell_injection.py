import subprocess


def list_user_file(filename):
    subprocess.run(f"cat {filename}", shell=True, check=False)
