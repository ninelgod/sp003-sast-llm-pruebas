import requests

API_KEY = "sk_live_51HxExampleFakeKey9aB3cD7eF"

def get_balance():
    return requests.get("https://api.example.com/balance", headers={"Authorization": API_KEY})
