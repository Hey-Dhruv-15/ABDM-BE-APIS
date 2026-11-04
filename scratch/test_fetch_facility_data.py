import requests
import json
import uuid
from datetime import datetime, timezone

base_url = "http://127.0.0.1:8000"
consent_id = "f47c3359-c3af-42a7-8a8a-56e63bc90739"
txn_id = f"txn-{uuid.uuid4()}"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Step 1: Trigger health information transfer (which packages the facility records, encrypts them, and pushes to health-information/data)
transfer_url = f"{base_url}/api/v1/health-information/transfer"
headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": str(uuid.uuid4()),
    "TIMESTAMP": now_iso,
    "Authorization": "Bearer test-jwt-token-12345"
}

transfer_payload = {
    "transactionId": txn_id,
    "consent": {
        "id": consent_id
    },
    "dateRange": {
        "from": "2024-01-01T00:00:00.000Z",
        "to": now_iso
    },
    "dataPushUrl": f"{base_url}/api/v1/health-information/data",
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

print(f"1. Triggering Health Information Transfer for Facility IN2910002343 (txn: {txn_id})...")
resp1 = requests.post(transfer_url, headers=headers, json=transfer_payload, timeout=10)
print(f"Transfer Response ({resp1.status_code}): {resp1.text}")

# Step 2: Query GET /api/v1/health-records to view all decrypted health data
get_url = f"{base_url}/api/v1/health-records"
print(f"\n2. Fetching records from {get_url}...")
resp2 = requests.get(get_url, headers={"accept": "application/json"}, timeout=10)
print(f"GET Records Response ({resp2.status_code}):")
print(json.dumps(resp2.json(), indent=2))
