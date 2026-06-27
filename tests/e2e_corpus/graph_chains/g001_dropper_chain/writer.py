from downloader import fetch_stage


def write_stage(url, target):
    data = fetch_stage(url)
    with open(target, "wb") as fp:
        fp.write(data)
    return target
