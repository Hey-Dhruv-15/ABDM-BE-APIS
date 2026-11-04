import requests
import json
import uuid
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8005"
CONSENT_ARTIFACT_ID = "consent-3efc551a-181b-4c95-9018-9a9b10f01f00"
PATIENT_ID = "sroshan110707@sbx"
NOW_ISO = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": str(uuid.uuid4()),
    "TIMESTAMP": NOW_ISO,
    "Authorization": "Bearer test-jwt-token-12345"
}

payload = {
    "consentArtifactId": CONSENT_ARTIFACT_ID,
    "patientId": PATIENT_ID,
    "dateFrom": "2024-01-01T00:00:00.000Z",
    "dateTo": NOW_ISO
}

print("=" * 80)
print("TESTING POST /api/v1/health-records/fetch-by-consent")
print(f"Target URL:          {BASE_URL}/api/v1/health-records/fetch-by-consent")
print(f"Consent Artifact ID: {CONSENT_ARTIFACT_ID}")
print(f"Patient ID:          {PATIENT_ID}")
print("=" * 80)

try:
    response = requests.post(
        f"{BASE_URL}/api/v1/health-records/fetch-by-consent",
        headers=headers,
        json=payload,
        timeout=15
    )
    print(f"HTTP Status: {response.status_code}")
    print("Response JSON:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error making request: {e}")

print("=" * 80)
