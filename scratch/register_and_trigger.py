import requests
import json
import uuid
from datetime import datetime, timezone

base_url = "http://127.0.0.1:8000"
# Register the tunnel the user is actively viewing on port 4041:
user_ngrok_url = "https://5d94-2409-40f2-209a-b053-406d-7559-a1f0-8708.ngrok-free.app"
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
    "url": user_ngrok_url
}

print(f"Registering Bridge URL: {user_ngrok_url} with ABDM Gateway...")
resp = requests.patch(patch_url, headers=headers, json=payload, timeout=10)
print(f"Status Code: {resp.status_code}")
print(f"Response: {resp.text}")

# Now trigger consent init so ABDM immediately hits this exact tunnel:
req_id = str(uuid.uuid4())
init_payload = {
    "requestId": req_id,
    "timestamp": now_iso,
    "consent": {
        "purpose": {
            "text": "Care Management",
            "code": "CAREMGT",
            "refUri": "www.abdm.gov.in"
        },
        "patient": {
            "id": "sroshan110707@sbx"
        },
        "hiu": {
            "id": "IN2910002345"
        },
        "hip": {
            "id": "IN2910002343"
        },
        "requester": {
            "name": "Agamin Innovations Pvt Ltd",
            "identifier": {
                "type": "REGNO1",
                "value": "MH1001",
                "system": "https://www.mciindia.org"
            }
        },
        "hiTypes": [
            "Prescription",
            "DiagnosticReport"
        ],
        "permission": {
            "accessMode": "VIEW",
            "dateRange": {
                "from": "2024-01-01T00:00:00.000Z",
                "to": now_iso
            },
            "dataEraseAt": "2026-12-31T23:59:59.000Z",
            "frequency": {
                "unit": "HOUR",
                "value": 0,
                "repeats": 0
            }
        }
    }
}

print(f"\nTriggering Consent Request (requestId: {req_id})...")
resp_init = requests.post(f"{base_url}/api/v1/consent-requests/init", headers=headers, json=init_payload, timeout=15)
print(f"Consent Init Status Code: {resp_init.status_code}")
print(f"Consent Init Body: {resp_init.text}")
