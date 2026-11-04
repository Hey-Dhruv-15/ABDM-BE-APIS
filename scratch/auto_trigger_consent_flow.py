import requests
import json
import uuid
from datetime import datetime, timezone
import time

base_url = "http://127.0.0.1:8005"
patient_id = "sroshan110707@sbx"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
req_id = str(uuid.uuid4())

headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": req_id,
    "TIMESTAMP": now_iso,
    "Authorization": "Bearer test-jwt-token"
}

print("=========================================================================")
print(f"STEP 1: INITIATING CONSENT REQUEST (POST {base_url}/api/v1/consent-requests/init)")
print("=========================================================================")
init_payload = {
    "requestId": req_id,
    "timestamp": now_iso,
    "consent": {
        "purpose": {
            "text": "Care Management",
            "code": "CAREMGT",
            "refUri": "https://www.abdm.gov.in"
        },
        "patient": {"id": patient_id},
        "hip": {"id": "IN2910002343"},
        "hiu": {"id": "IN2910002345"},
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
            "WellnessRecord",
            "Invoice"
        ],
        "permission": {
            "accessMode": "VIEW",
            "dateRange": {
                "from": "2025-01-01T00:00:00.000Z",
                "to": now_iso
            },
            "dataEraseAt": "2027-12-31T23:59:59.000Z",
            "frequency": {"unit": "HOUR", "value": 1, "repeats": 0}
        }
    }
}

r1 = requests.post(f"{base_url}/api/v1/consent-requests/init", headers=headers, json=init_payload, timeout=10)
print(f"Status Code: {r1.status_code}")
print(f"Consent Request ID: {req_id}\n")

time.sleep(1)

print("=========================================================================")
print(f"STEP 2: AUTOMATICALLY TRIGGERING CONSENT GRANT WEBHOOK CALLBACK")
print("=========================================================================")
art_id = str(uuid.uuid4())
grant_payload = {
    "requestId": str(uuid.uuid4()),
    "timestamp": now_iso,
    "notification": {
        "consentRequestId": req_id,
        "status": "GRANTED",
        "consentArtefacts": [
            {"id": art_id}
        ]
    }
}

r2 = requests.post(f"{base_url}/api/v1/consents/hiu/notify", headers=headers, json=grant_payload, timeout=10)
print(f"Webhook Trigger Status: {r2.status_code}")
print(f"Generated Consent Artefact ID: {art_id}\n")

time.sleep(1)

print("=========================================================================")
print(f"STEP 3: VERIFYING UPDATED STATUS VIA GET /api/v1/consent-requests/{req_id}")
print("=========================================================================")
r3 = requests.get(f"{base_url}/api/v1/consent-requests/{req_id}", headers=headers, timeout=10)
print(f"Status: {r3.status_code}")
print(json.dumps(r3.json(), indent=2))
