import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.abdm.json_storage import read_storage
from app.abdm.auth import ABDMAuthService
from app.abdm.client import ABDMGatewayClient
from app.api.dependencies import set_abdm_auth_service, set_abdm_gateway_client

async def test_auto_generated_consent():
    auth_service = ABDMAuthService()
    client = ABDMGatewayClient(auth_service)
    set_abdm_auth_service(auth_service)
    set_abdm_gateway_client(client)
    
    # Payload WITHOUT requestId and WITHOUT timestamp
    payload_without_ids = {
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
        "Authorization": "Bearer test-jwt-token-12345"
    }
    
    print("[*] Dispatching Consent Request (without requestId and timestamp)...")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client_http:
        resp = await client_http.post("/api/v1/consent-requests/init", headers=headers, json=payload_without_ids)
        print(f"[*] Response Status Code: {resp.status_code}")
        print(f"[*] Server Response: {resp.text}")
        
    storage = read_storage("consent_requests")
    resp_json = resp.json()
    new_req_id = resp_json.get("requestId")
    print(f"[*] Auto-Generated Request ID: {new_req_id}")
    print(f"[*] Auto-Generated Timestamp: {resp_json.get('timestamp')}")
    print(f"[*] Saved into consent_requests.json: {new_req_id in storage}")

if __name__ == "__main__":
    asyncio.run(test_auto_generated_consent())
