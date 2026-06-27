import requests


def fetch_profile(user_id):
    response = requests.get(f"https://api.example.invalid/users/{user_id}", timeout=5)
    return response.json()
