import sys
sys.path.insert(0, ".")
import requests
import json
import uuid
from datetime import datetime, timezone
from app.services.health_exchange import HealthInfoCryptoService

base_url = "http://127.0.0.1:8000"
consent_id = "f47c3359-c3af-42a7-8a8a-56e63bc90739"
txn_id = f"txn-{uuid.uuid4()}"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Generate valid X25519 HIU key pair for the transaction
hiu_priv_b64, hiu_pub_b64 = HealthInfoCryptoService.generate_key_pair()
hiu_nonce = HealthInfoCryptoService.generate_key_pair()[1]

# Step 1: Health Information Request (HIU requests health records for Facility IN2910002343)
req_payload = {
    "requestId": str(uuid.uuid4()),
    "timestamp": now_iso,
    "transactionId": txn_id,
    "hiRequest": {
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
                "keyValue": hiu_pub_b64
            },
            "nonce": hiu_nonce
        }
    }
}

headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": str(uuid.uuid4()),
    "TIMESTAMP": now_iso,
    "Authorization": "Bearer test-jwt-token-12345"
}

print(f"1. Requesting Health Information for Facility IN2910002343 (txn: {txn_id})...")
resp1 = requests.post(f"{base_url}/api/v1/health-information/request", headers=headers, json=req_payload, timeout=10)
print(f"Request response ({resp1.status_code}): {resp1.text}")

# Step 2: Push Data (HIP packages facility data & encrypts using HIU's public key)
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
            "keyValue": hiu_pub_b64
        },
        "nonce": hiu_nonce
    }
}

print(f"\n2. Transferring and pushing health records...")
resp2 = requests.post(f"{base_url}/api/v1/health-information/transfer", headers=headers, json=transfer_payload, timeout=10)
print(f"Transfer response ({resp2.status_code}): {resp2.text}")

# Step 3: Fetch Decrypted Records from GET /api/v1/health-records/{txn_id}
print(f"\n3. Fetching decrypted medical records from GET /api/v1/health-records/{txn_id}...")
resp3 = requests.get(f"{base_url}/api/v1/health-records/{txn_id}", headers={"accept": "application/json"}, timeout=10)
print(f"Records Response ({resp3.status_code}):")
print(json.dumps(resp3.json(), indent=2))
