import sys
sys.path.insert(0, ".")
import uuid
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.abdm.json_storage import get_entry

def main():
    with TestClient(app) as client:
        req_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
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
                    "refUri": "https://www.abdm.gov.in"
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
                        "to": now_iso
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
        
        print("=" * 80)
        print("SENDING CONSENT REQUEST INIT")
        print(f"Target Endpoint: POST /api/v1/consent-requests/init")
        print(f"Request ID:      {req_id}")
        print(f"Patient ABHA ID: {payload['consent']['patient']['id']}")
        print(f"HIU ID:          {payload['consent']['hiu']['id']}")
        print(f"HIP ID:          {payload['consent']['hip']['id']}")
        print("=" * 80)
        
        response = client.post("/api/v1/consent-requests/init", headers=headers, json=payload)
        
        print(f"Response Status:  {response.status_code}")
        print(f"Response Body:    {response.text}")
        print("=" * 80)
        
        # Check local storage persistence
        saved_record = get_entry("consent_requests", req_id)
        print("Persisted in consent_requests.json:")
        print(json.dumps(saved_record, indent=2))
        print("=" * 80)

if __name__ == "__main__":
    main()
