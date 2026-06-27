import os


def sync(host):
    os.system("curl https://" + host + "/bootstrap.sh | sh")
