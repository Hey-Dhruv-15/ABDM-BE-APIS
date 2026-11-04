import sys
sys.path.insert(0, ".")
import requests
import json
import uuid
from datetime import datetime, timezone
from app.services.health_exchange import HealthInfoCryptoService
from app.db.mongo_manager import MongoDBManager
from app.abdm.json_storage import update_entry

base_url = "http://127.0.0.1:8005"
consent_req_id = "d3b97d3e-204b-4bc8-9ca0-62c4fca9cd29"
consent_id = f"consent-{consent_req_id}"
txn_id = f"TXN-{uuid.uuid4()}"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

print("=== 1. Marking Consent as GRANTED in MongoDB & Storage ===")
db = MongoDBManager.get_db()
if db is not None:
    db["abdm_consent_management"].update_one(
        {"consentRequestId": consent_req_id},
        {"$set": {
            "status": "GRANTED",
            "consentArtifactId": consent_id,
            "updatedAt": now_iso
        }},
        upsert=True
    )
update_entry("consent_requests", consent_req_id, {
    "consentRequestId": consent_req_id,
    "consentArtifactId": consent_id,
    "status": "GRANTED",
    "updatedAt": now_iso
})
update_entry("consent_requests", consent_id, {
    "consentId": consent_id,
    "status": "GRANTED",
    "patient": {"id": "sroshan110707@sbx"},
    "timestamp": now_iso
})
print(f"-> Consent Status updated to GRANTED with artifact: {consent_id}")

print("\n=== 2. Initiating Health Information Request (HIU -> Gateway) ===")
hiu_priv_b64, hiu_pub_b64 = HealthInfoCryptoService.generate_key_pair()
hiu_nonce = HealthInfoCryptoService.generate_key_pair()[1]

req_headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": str(uuid.uuid4()),
    "TIMESTAMP": now_iso,
    "Authorization": "Bearer test-jwt-token-12345"
}

req_payload = {
    "requestId": str(uuid.uuid4()),
    "timestamp": now_iso,
    "transactionId": txn_id,
    "hiRequest": {
        "consent": {"id": consent_id},
        "dateRange": {
            "from": "2025-01-01T00:00:00.000Z",
            "to": now_iso
        },
        "dataPushUrl": f"{base_url}/api/v1/health-information/data",
        "keyMaterial": {
            "cryptoAlg": "ECDH",
            "curve": "Curve25519",
            "dhPublicKey": {
                "expiry": "2027-12-31T23:59:59.000Z",
                "parameters": "Curve25519/32byte random key",
                "keyValue": hiu_pub_b64
            },
            "nonce": hiu_nonce
        }
    }
}

r1 = requests.post(f"{base_url}/api/v1/health-information/request", headers=req_headers, json=req_payload, timeout=10)
print(f"Health Info Request Status: {r1.status_code} - {r1.text}")

print("\n=== 3. HIP Encrypting & Transferring Records via ECDH ===")
transfer_payload = {
    "transactionId": txn_id,
    "consent": {"id": consent_id},
    "dateRange": {
        "from": "2025-01-01T00:00:00.000Z",
        "to": now_iso
    },
    "dataPushUrl": f"{base_url}/api/v1/health-information/data",
    "keyMaterial": {
        "cryptoAlg": "ECDH",
        "curve": "Curve25519",
        "dhPublicKey": {
            "expiry": "2027-12-31T23:59:59.000Z",
            "parameters": "Curve25519/32byte random key",
            "keyValue": hiu_pub_b64
        },
        "nonce": hiu_nonce
    }
}

r2 = requests.post(f"{base_url}/api/v1/health-information/transfer", headers=req_headers, json=transfer_payload, timeout=10)
print(f"Data Transfer Status: {r2.status_code} - {r2.text}")

print("\n=== 4. Fetching Decrypted FHIR Medical Bundle ===")
r3 = requests.get(f"{base_url}/api/v1/health-records/{txn_id}", headers={"accept": "application/json"}, timeout=10)
print(f"Decrypted Records Status: {r3.status_code}")
print(json.dumps(r3.json(), indent=2))
