import base64


def dangerous_exec():
    payload = "cHJpbnQoJ3B3bmVkJyk="
    exec(base64.b64decode(payload))


def run_payload():
    payload = "cHJpbnQoJ3N0YWdlMicp"
    exec(base64.b64decode(payload).decode())

