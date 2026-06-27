def write_plugin(path):
    with open(path, "w", encoding="utf-8") as fp:
        fp.write("def run():\n    return 'stage2'\n")
    return path
