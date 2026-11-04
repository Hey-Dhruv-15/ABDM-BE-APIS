import requests
import json
import uuid
from datetime import datetime, timezone

base_url = "http://127.0.0.1:8000"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

url = f"{base_url}/api/v1/hiecm/gateway/v3/bridge-services"
headers = {
    "accept": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": str(uuid.uuid4()),
    "TIMESTAMP": now_iso,
    "Authorization": "Bearer test-jwt-token-12345"
}

print(f"Checking linked bridge services from ABDM Gateway...")
try:
    resp = requests.get(url, headers=headers, timeout=10)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")
except Exception as e:
    print(f"Error: {e}")
