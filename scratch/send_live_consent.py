import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import asyncio
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.abdm.json_storage import read_storage
from app.abdm.auth import ABDMAuthService
from app.abdm.client import ABDMGatewayClient
from app.api.dependencies import set_abdm_auth_service, set_abdm_gateway_client

async def trigger_consent():
    auth_service = ABDMAuthService()
    client = ABDMGatewayClient(auth_service)
    set_abdm_auth_service(auth_service)
    set_abdm_gateway_client(client)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    req_id = str(uuid.uuid4())
    
    consent_payload = {
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
                    "to": "2026-09-29T11:00:00.000Z"
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
    
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "X-Region": "india",
        "X-CM-ID": "sbx",
        "REQUEST-ID": req_id,
        "TIMESTAMP": now_iso,
        "Authorization": "Bearer test-jwt-token-12345"
    }
    
    print(f"[*] Sending Consent Request for patient: sroshan110707@sbx (requestId: {req_id})...")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/consent-requests/init", headers=headers, json=consent_payload)
        print(f"[*] HTTP Status: {resp.status_code}")
        print(f"[*] Response Body: {resp.text}")
        
    storage = read_storage("consent_requests")
    print(f"[*] Entry in consent_requests.json saved: {req_id in storage}")
    if req_id in storage:
        print(f"[*] Saved Consent Record: {storage[req_id]}")

if __name__ == "__main__":
    asyncio.run(trigger_consent())
