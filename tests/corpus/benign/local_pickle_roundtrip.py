import pickle


def roundtrip(value):
    data = pickle.dumps(value)
    return pickle.loads(data)

