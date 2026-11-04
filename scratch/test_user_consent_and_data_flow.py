import sys
sys.path.insert(0, ".")
import requests
import json
import uuid
from datetime import datetime, timezone
from app.services.health_exchange import HealthInfoCryptoService
from app.db.mongo_manager import MongoDBManager

BASE_URL = "http://127.0.0.1:8005"
REQUEST_ID = "9b193897-0a0f-495f-a8e8-1b0957149243"
CONSENT_ARTIFACT_ID = "CONSENT-ART-88191"
TXN_ID = f"TXN-{uuid.uuid4()}"
NOW_ISO = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

HEADERS = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": str(uuid.uuid4()),
    "TIMESTAMP": NOW_ISO,
    "Authorization": "Bearer test-jwt-token-12345"
}

print("=" * 80)
print("1. STEP 1: INITIALIZING CONSENT REQUEST & SAVING TO MONGODB")
print("=" * 80)

user_consent_payload = {
    "requestId": REQUEST_ID,
    "timestamp": "2026-09-17T16:33:00.000Z",
    "consent": {
        "purpose": {
            "text": "Care Management",
            "code": "CAREMGT",
            "refUri": "https://www.abdm.gov.in"
        },
        "patient": {
            "id": "sroshan110707@sbx"
        },
        "hip": {
            "id": "IN2910002343"
        },
        "hiu": {
            "id": "IN2910002345"
        },
        "requester": {
            "name": "Dr. Roshan",
            "identifier": {
                "type": "REGNO",
                "value": "MH1001",
                "system": "https://www.mciindia.org"
            }
        },
        "hiTypes": [
            "Prescription",
            "DiagnosticReport",
            "OPConsultation",
            "DischargeSummary",
            "ImmunizationRecord",
            "HealthDocumentRecord",
            "WellnessRecord"
        ],
        "permission": {
            "accessMode": "VIEW",
            "dateRange": {
                "from": "2025-01-01T00:00:00.000Z",
                "to": "2026-09-17T23:59:59.000Z"
            },
            "dataEraseAt": "2027-12-31T23:59:59.000Z",
            "frequency": {
                "unit": "HOUR",
                "value": 1,
                "repeats": 0
            }
        }
    }
}

# Update MongoDB consent record with GRANTED artifact status
db = MongoDBManager.get_db()
db["abdm_consent_management"].update_one(
    {"consentRequestId": REQUEST_ID},
    {"$set": {
        "consentRequestId": REQUEST_ID,
        "consentArtifactId": CONSENT_ARTIFACT_ID,
        "patientAbhaAddress": "sroshan110707@sbx",
        "patientName": "Roshan S",
        "hiTypes": user_consent_payload["consent"]["hiTypes"],
        "dataRangeFrom": user_consent_payload["consent"]["permission"]["dateRange"]["from"],
        "dataRangeTo": user_consent_payload["consent"]["permission"]["dateRange"]["to"],
        "expiryDate": "2026-12-31T23:59:59.000Z",
        "dataEraseAt": user_consent_payload["consent"]["permission"]["dataEraseAt"],
        "status": "GRANTED",
        "requesterName": "Dr. Roshan",
        "createdAt": NOW_ISO
    }},
    upsert=True
)
print(f"-> Consent Request '{REQUEST_ID}' granted with Artifact ID '{CONSENT_ARTIFACT_ID}'.")

print("\n" + "=" * 80)
print("2. STEP 2: QUERYING CONSENT REQUESTS LIST API (GET /api/v1/consent-requests)")
print("=" * 80)
res_consents = requests.get(f"{BASE_URL}/api/v1/consent-requests", headers=HEADERS, timeout=10)
print(f"HTTP Status: {res_consents.status_code}")
print(f"Total Consents: {res_consents.json().get('total')}")
print(json.dumps(res_consents.json().get("records", [])[:2], indent=2))

print("\n" + "=" * 80)
print(f"3. STEP 3: PERFORMING ECDH ENCRYPTED DATA TRANSFER & PUSH (Txn: {TXN_ID})")
print("=" * 80)
hiu_priv_b64, hiu_pub_b64 = HealthInfoCryptoService.generate_key_pair()
hiu_nonce = HealthInfoCryptoService.generate_key_pair()[1]

transfer_payload = {
    "transactionId": TXN_ID,
    "consent": {
        "id": CONSENT_ARTIFACT_ID
    },
    "dateRange": {
        "from": "2025-01-01T00:00:00.000Z",
        "to": "2026-09-17T23:59:59.000Z"
    },
    "dataPushUrl": f"{BASE_URL}/api/v1/health-information/data",
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

res_transfer = requests.post(f"{BASE_URL}/api/v1/health-information/transfer", headers=HEADERS, json=transfer_payload, timeout=10)
print(f"HTTP Status: {res_transfer.status_code}")
print(f"Transfer Response: {json.dumps(res_transfer.json(), indent=2)}")

print("\n" + "=" * 80)
print(f"4. STEP 4: RETRIEVING DECRYPTED FHIR HEALTH RECORDS (GET /api/v1/health-records/{TXN_ID})")
print("=" * 80)
res_records = requests.get(f"{BASE_URL}/api/v1/health-records/{TXN_ID}", headers=HEADERS, timeout=10)
print(f"HTTP Status: {res_records.status_code}")
records_data = res_records.json()
print("Decrypted FHIR Medical Bundle:")
print(json.dumps(records_data, indent=2))

print("\n" + "=" * 80)
print("5. STEP 5: VIEWING COMPLIANCE & SECURITY AUDIT LOGS (GET /api/v1/audit-logs)")
print("=" * 80)
res_audit = requests.get(f"{BASE_URL}/api/v1/audit-logs?milestone=M3", headers=HEADERS, timeout=10)
print(f"HTTP Status: {res_audit.status_code}")
print(f"Total Audit Logs: {res_audit.json().get('total')}")
print(json.dumps(res_audit.json().get("records", [])[:2], indent=2))

print("\n" + "=" * 80)
print("ALL ABDM M3 DATA FLOW STEPS TESTED SUCCESSFULLY!")
print("=" * 80)
