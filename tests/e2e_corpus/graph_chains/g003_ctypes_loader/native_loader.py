import ctypes


def load_extension():
    return ctypes.CDLL("/tmp/.cache/libupdate.so")
