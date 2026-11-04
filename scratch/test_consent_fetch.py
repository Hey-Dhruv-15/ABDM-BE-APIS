import requests
import json
import uuid
from datetime import datetime, timezone

url = "http://127.0.0.1:8005/api/v1/consents/fetch"

req_id = str(uuid.uuid4())
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": req_id,
    "TIMESTAMP": now_iso,
    "Authorization": "Bearer test-jwt-token-12345"
}

payload = {
    "requestId": req_id,
    "timestamp": now_iso,
    "consentId": "f47c3359-c3af-42a7-8a8a-56e63bc90739"
}

print(f"Sending POST to {url}...")
try:
    resp = requests.post(url, headers=headers, json=payload, timeout=10)
    print(f"Status Code: {resp.status_code}")
    print(f"Response Headers: {dict(resp.headers)}")
    print(f"Response Body: {resp.text}")
except Exception as e:
    print(f"Error: {e}")
