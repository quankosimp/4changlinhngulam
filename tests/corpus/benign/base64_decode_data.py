import base64


def decode_label():
    return base64.b64decode("SGVsbG8=").decode()

