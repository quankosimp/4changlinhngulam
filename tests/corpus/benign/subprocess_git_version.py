import subprocess


def git_version():
    return subprocess.run(["git", "--version"], check=False)
