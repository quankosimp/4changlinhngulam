import json


def write_report(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)

