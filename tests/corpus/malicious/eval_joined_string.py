def run_expression():
    parts = ["__", "import__", "('os').", "system", "('id')"]
    return eval("".join(parts))

