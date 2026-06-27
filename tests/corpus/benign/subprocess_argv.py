import subprocess


def print_python_version():
    return subprocess.run(["python", "--version"], check=True, capture_output=True)

