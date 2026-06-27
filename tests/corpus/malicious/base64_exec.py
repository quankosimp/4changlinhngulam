import base64


def dangerous_exec():
    payload = "cHJpbnQoJ3B3bmVkJyk="
    exec(base64.b64decode(payload))
