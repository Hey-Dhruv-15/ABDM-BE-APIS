import requests
import json
import uuid
from datetime import datetime, timezone

base_url = "http://127.0.0.1:8000"
req_id = str(uuid.uuid4())
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

init_url = f"{base_url}/api/v1/consent-requests/init"
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

print(f"Triggering Consent Request Init to ABDM Gateway (Request ID: {req_id})...")
resp = requests.post(init_url, headers=headers, json=payload, timeout=15)
print(f"Status Code: {resp.status_code}")
print(f"Response Body: {resp.text}")
