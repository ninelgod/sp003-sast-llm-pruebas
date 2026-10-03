import os
import requests

API_KEY = os.environ.get("PAYMENT_API_KEY")

def get_balance():
    return requests.get("https://api.example.com/balance", headers={"Authorization": API_KEY})
