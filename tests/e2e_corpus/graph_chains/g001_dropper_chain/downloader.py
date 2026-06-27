import requests


def fetch_stage(url):
    return requests.get(url).content
