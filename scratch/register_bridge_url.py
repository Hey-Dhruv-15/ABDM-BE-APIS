import requests
import json
import uuid
from datetime import datetime, timezone

base_url = "http://127.0.0.1:8000"
ngrok_url = "https://1111-2409-40f2-209a-b053-406d-7559-a1f0-8708.ngrok-free.app"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

patch_url = f"{base_url}/api/v1/hiecm/gateway/v3/bridge/url"
headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": str(uuid.uuid4()),
    "TIMESTAMP": now_iso,
    "Authorization": "Bearer test-jwt-token-12345"
}

payload = {
    "url": ngrok_url
}

print(f"Registering Bridge URL with ABDM Gateway: {ngrok_url}...")
try:
    resp = requests.patch(patch_url, headers=headers, json=payload, timeout=10)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")
except Exception as e:
    print(f"Error: {e}")
