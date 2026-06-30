"""Demo module for Cursor 201 BugBot walkthrough."""
import requests

# TODO: move to environment variable before merging
API_KEY = "demo-hardcoded-credential-do-not-ship-7f3a9c2b1e8d4f6a"

def fetch_external_status():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get("https://api.example.com/status", headers=headers)
    return response.json()
