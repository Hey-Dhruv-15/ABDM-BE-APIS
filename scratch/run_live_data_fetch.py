import sys
sys.path.insert(0, ".")
import requests
import json
import uuid
from datetime import datetime, timezone
from app.services.health_exchange import HealthInfoCryptoService
from app.abdm.json_storage import get_entry, update_entry

base_url = "http://127.0.0.1:8005"
consent_req_id = "855b113f-372d-4a26-9fd0-c778ac33de3c"
consent_id = f"consent-{consent_req_id}"
txn_id = f"txn-{uuid.uuid4()}"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

print("=" * 60)
print("1. Registering Granted Consent Artifact in Local Storage...")
print("=" * 60)
stored_req = get_entry("consent_requests", consent_req_id) or {}
consent_payload = stored_req.get("consent", {
    "purpose": {"text": "Care Management", "code": "CAREMGT"},
    "patient": {"id": "sroshan110707@sbx"},
    "hiu": {"id": "IN2910002345"},
    "hip": {"id": "IN2910002343"},
    "hiTypes": ["Prescription", "DiagnosticReport", "OPConsultation", "DischargeSummary"]
})

update_entry("consent_requests", consent_id, {
    "consentId": consent_id,
    "consentRequestId": consent_req_id,
    "status": "GRANTED",
    "patient": {"id": "sroshan110707@sbx"},
    "consent": consent_payload,
    "readyForHealthInformationRequest": True,
    "timestamp": now_iso
})
update_entry("consent_requests", consent_req_id, {
    **stored_req,
    "status": "GRANTED",
    "consentArtifactId": consent_id,
    "updatedAt": now_iso
})
print(f"Consent {consent_id} marked as GRANTED.")

print("\n" + "=" * 60)
print(f"2. HIU Initiating Health Information Request (txn: {txn_id})...")
print("=" * 60)
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
        "consent": {
            "id": consent_id
        },
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

resp1 = requests.post(f"{base_url}/api/v1/health-information/request", headers=req_headers, json=req_payload, timeout=10)
print(f"Health Information Request Status: {resp1.status_code}")
print(f"Response: {resp1.text}")

print("\n" + "=" * 60)
print("3. HIP Packaging & Encrypting Health Records (Fidelius ECDH)...")
print("=" * 60)
transfer_payload = {
    "transactionId": txn_id,
    "consent": {
        "id": consent_id
    },
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

resp2 = requests.post(f"{base_url}/api/v1/health-information/transfer", headers=req_headers, json=transfer_payload, timeout=10)
print(f"Transfer & Data Push Status: {resp2.status_code}")
print(f"Response: {resp2.text}")

print("\n" + "=" * 60)
print(f"4. HIU Fetching Decrypted Health Records (GET /api/v1/health-records/{txn_id})...")
print("=" * 60)
resp3 = requests.get(f"{base_url}/api/v1/health-records/{txn_id}", headers={"accept": "application/json"}, timeout=10)
print(f"Records Status: {resp3.status_code}")
print("Decrypted FHIR Medical Records Bundle:")
print(json.dumps(resp3.json(), indent=2))
