import sys
sys.path.insert(0, ".")
import asyncio
import json
import uuid
from datetime import datetime, timezone
import httpx
from httpx import ASGITransport

from app.main import app
from app.lifecycle import lifespan
from app.services.health_exchange import HealthInfoCryptoService
from app.abdm.json_storage import update_entry, get_entry, read_storage

user_payload = {
    "requestId": "9b193897-0a0f-495f-a8e8-1b0957149243",
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
            "WellnessRecord",
            "Invoice"
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

async def run_m3_test():
    async with lifespan(app):
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            print("=" * 60)
            print("STEP 1: Testing POST /api/v1/consent-requests/init")
            print("=" * 60)
            
            headers = {
                "accept": "application/json",
                "Content-Type": "application/json",
                "X-Region": "india",
                "X-CM-ID": "sbx",
                "REQUEST-ID": user_payload["requestId"],
                "TIMESTAMP": user_payload["timestamp"],
                "Authorization": "Bearer test-jwt-token-12345"
            }
            
            resp = await client.post("/api/v1/consent-requests/init", headers=headers, json=user_payload)
            print(f"Status: {resp.status_code}")
            print(f"Response: {resp.text}")
            assert resp.status_code == 200, f"Expected 200 but got {resp.status_code}"
            
            req_id = user_payload["requestId"]
            
            print("\n" + "=" * 60)
            print("STEP 2: Verify Consent Request stored locally")
            print("=" * 60)
            consent_entry = get_entry("consent_requests", req_id)
            print(f"Stored Consent Entry: {json.dumps(consent_entry, indent=2)}")
            assert consent_entry is not None, "Consent entry was not stored!"
            
            print("\n" + "=" * 60)
            print("STEP 3: Testing Consent Notification / Grant Simulation")
            print("=" * 60)
            consent_id = f"consent-{uuid.uuid4()}"
            notify_payload = {
                "requestId": str(uuid.uuid4()),
                "timestamp": "2026-09-17T16:35:00.000Z",
                "notification": {
                    "consentRequestId": req_id,
                    "status": "GRANTED",
                    "consentArtefacts": [
                        {"id": consent_id}
                    ]
                }
            }
            notify_headers = {
                "Content-Type": "application/json",
                "X-Region": "india",
                "X-CM-ID": "sbx",
                "REQUEST-ID": notify_payload["requestId"],
                "TIMESTAMP": notify_payload["timestamp"],
                "Authorization": "Bearer test-jwt-token-12345"
            }
            resp_notify = await client.post("/api/v1/consents/hip/notify", headers=notify_headers, json=notify_payload)
            print(f"Notify Status: {resp_notify.status_code}, Response: {resp_notify.text}")

            # Also store granted consent artifact for subsequent health info request
            update_entry("consent_requests", consent_id, {
                "consentId": consent_id,
                "consentRequestId": req_id,
                "status": "GRANTED",
                "consent": user_payload["consent"],
                "readyForHealthInformationRequest": True,
                "timestamp": "2026-09-17T16:35:00.000Z"
            })

            print("\n" + "=" * 60)
            print("STEP 4: Testing Health Information Request (HIU -> HIP)")
            print("=" * 60)
            txn_id = f"txn-{uuid.uuid4()}"
            hiu_priv_b64, hiu_pub_b64 = HealthInfoCryptoService.generate_key_pair()
            hiu_nonce = HealthInfoCryptoService.generate_key_pair()[1]

            hi_request_payload = {
                "requestId": str(uuid.uuid4()),
                "timestamp": "2026-09-17T16:36:00.000Z",
                "transactionId": txn_id,
                "hiRequest": {
                    "consent": {
                        "id": consent_id
                    },
                    "dateRange": {
                        "from": "2025-01-01T00:00:00.000Z",
                        "to": "2026-09-17T23:59:59.000Z"
                    },
                    "dataPushUrl": "http://testserver/api/v1/health-information/data",
                    "keyMaterial": {
                        "cryptoAlg": "ECDH",
                        "curve": "Curve25519",
                        "dhPublicKey": {
                            "expiry": "2027-12-31T23:59:59.000Z",
                            "parameters": "Curve25519/32byte",
                            "keyValue": hiu_pub_b64
                        },
                        "nonce": hiu_nonce
                    }
                }
            }
            
            hi_headers = {
                "accept": "application/json",
                "Content-Type": "application/json",
                "X-Region": "india",
                "X-CM-ID": "sbx",
                "REQUEST-ID": hi_request_payload["requestId"],
                "TIMESTAMP": hi_request_payload["timestamp"],
                "Authorization": "Bearer test-jwt-token-12345"
            }
            resp_hireq = await client.post("/api/v1/health-information/request", headers=hi_headers, json=hi_request_payload)
            print(f"HI-Request Status: {resp_hireq.status_code}, Response: {resp_hireq.text}")
            assert resp_hireq.status_code == 200, f"Expected 200 but got {resp_hireq.status_code}"

            print("\n" + "=" * 60)
            print("STEP 5: Testing Health Information Transfer & Push (HIP -> HIU)")
            print("=" * 60)
            transfer_payload = {
                "transactionId": txn_id,
                "consent": {
                    "id": consent_id
                },
                "dateRange": {
                    "from": "2025-01-01T00:00:00.000Z",
                    "to": "2026-09-17T23:59:59.000Z"
                },
                "dataPushUrl": "http://testserver/api/v1/health-information/data",
                "keyMaterial": {
                    "cryptoAlg": "ECDH",
                    "curve": "Curve25519",
                    "dhPublicKey": {
                        "expiry": "2027-12-31T23:59:59.000Z",
                        "parameters": "Curve25519/32byte",
                        "keyValue": hiu_pub_b64
                    },
                    "nonce": hiu_nonce
                }
            }
            resp_transfer = await client.post("/api/v1/health-information/transfer", headers=hi_headers, json=transfer_payload)
            print(f"Transfer Status: {resp_transfer.status_code}, Response: {resp_transfer.text}")
            assert resp_transfer.status_code == 200, f"Expected 200 but got {resp_transfer.status_code}"

            print("\n" + "=" * 60)
            print(f"STEP 6: Testing GET /api/v1/health-records/{txn_id}")
            print("=" * 60)
            resp_records = await client.get(f"/api/v1/health-records/{txn_id}")
            print(f"Records Status: {resp_records.status_code}")
            print(f"Decrypted Health Records:\n{json.dumps(resp_records.json(), indent=2)}")
            assert resp_records.status_code == 200, f"Expected 200 but got {resp_records.status_code}"

            print("\n" + "=" * 60)
            print("STEP 7: Testing GET /api/v1/consent-requests & GET /api/v1/consent-requests/{id}")
            print("=" * 60)
            resp_mgmt = await client.get("/api/v1/consent-requests", headers={"X-Region": "india", "Authorization": "Bearer test-jwt-token-12345"})
            print(f"Consent Requests List Status: {resp_mgmt.status_code}")
            assert resp_mgmt.status_code == 200, f"Expected 200 but got {resp_mgmt.status_code}"
            data = resp_mgmt.json()
            print(f"List Response (Found {len(data.get('records', []))} records):\n{json.dumps(data, indent=2)}")

            resp_single = await client.get(f"/api/v1/consent-requests/{req_id}", headers={"X-Region": "india", "Authorization": "Bearer test-jwt-token-12345"})
            print(f"\nSingle Consent Request Status: {resp_single.status_code}")
            assert resp_single.status_code == 200, f"Expected 200 but got {resp_single.status_code}"
            print(f"Single Request Details:\n{json.dumps(resp_single.json(), indent=2)}")

            print("\n" + "=" * 60)
            print("ALL M3 API TESTS PASSED 100% SUCCESSFULLY!")
            print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_m3_test())
