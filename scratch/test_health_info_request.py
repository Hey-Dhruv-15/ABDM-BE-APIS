import requests
import json
import uuid
from datetime import datetime, timezone

url = "http://127.0.0.1:8000/api/v1/health-information/request"

req_id = str(uuid.uuid4())
txn_id = f"txn-{uuid.uuid4()}"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
ngrok_base = "https://1111-2409-40f2-209a-b053-406d-7559-a1f0-8708.ngrok-free.app"

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
    "transactionId": txn_id,
    "hiRequest": {
        "consent": {
            "id": "f47c3359-c3af-42a7-8a8a-56e63bc90739"
        },
        "dateRange": {
            "from": "2024-01-01T00:00:00.000Z",
            "to": now_iso
        },
        "dataPushUrl": f"{ngrok_base}/api/v1/health-information/transfer",
        "keyMaterial": {
            "cryptoAlg": "ECDH",
            "curve": "Curve25519",
            "dhPublicKey": {
                "expiry": "2026-12-31T23:59:59.000Z",
                "parameters": "Curve25519/32byte random key",
                "keyValue": "BCpsBW37KgfLyjxJK0zHHG26hDjxzK368DEO4PapzFhQM0cghZziKuvJh5/anTnHitVHKMn0Owr1HvcH1fm0DpA="
            },
            "nonce": "0ka0stPfqmXWhX+ODC/iOFMO0PXFdRjBdcEGbv55qqc="
        }
    }
}

print(f"Sending POST to {url}...")
try:
    resp = requests.post(url, headers=headers, json=payload, timeout=10)
    print(f"Status Code: {resp.status_code}")
    print(f"Response Headers: {dict(resp.headers)}")
    print(f"Response Body: {resp.text}")
except Exception as e:
    print(f"Error: {e}")
