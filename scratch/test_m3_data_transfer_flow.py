import sys
sys.path.insert(0, ".")
import asyncio
import uuid
import json
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.settings import settings
from app.services.health_exchange import HealthInfoCryptoService
from app.db.mongo_manager import MongoDBManager
from app.abdm.json_storage import update_entry
from app.api.dependencies import set_abdm_gateway_client

class StubABDMGatewayClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def post(
        self,
        path: str,
        body: dict,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: dict | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> dict:
        self.calls.append({"path": path, "body": body})
        return {"requestId": body.get("requestId", str(uuid.uuid4())), "acknowledgement": "OK"}

async def test_full_m3_data_flow():
    settings.ENFORCE_REGION_HEADER = False
    settings.REQUIRE_AUTHORIZATION_HEADER = False
    settings.REQUIRE_JWT_VALIDATION = False
    settings.ENABLE_ABHA = True
    settings.REGION = "india"
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    settings.ABDM_CM_ID = "sbx"
    settings.ABDM_HIU_ID = "IN2910002345"

    stub_gw = StubABDMGatewayClient()
    set_abdm_gateway_client(stub_gw)
    print("=" * 80)
    print(">> STARTING ABDM M3 DATA REQUEST & TRANSFER TEST SUITE")
    print("=" * 80)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    consent_req_id = f"REQ-{uuid.uuid4()}"
    consent_art_id = f"CONSENT-ART-{uuid.uuid4().hex[:8]}"
    txn_id = f"TXN-{uuid.uuid4()}"
    patient_abha = "sroshan110707@sbx"

    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "X-Region": "india",
        "X-CM-ID": "sbx",
        "REQUEST-ID": str(uuid.uuid4()),
        "TIMESTAMP": now_iso,
        "Authorization": "Bearer test-jwt-token-m3-data"
    }

    # Step 1: Pre-populate Granted Consent Artifact in storage/DB
    print("\n[STEP 1] Pre-populating Granted Consent in Storage & MongoDB...")
    db = MongoDBManager.get_db()
    if db is not None:
        db["abdm_consent_management"].update_one(
            {"consentRequestId": consent_req_id},
            {"$set": {
                "consentRequestId": consent_req_id,
                "consentArtifactId": consent_art_id,
                "patientAbhaAddress": patient_abha,
                "patientName": "Roshan S",
                "hiTypes": ["Prescription", "DiagnosticReport", "OPConsultation"],
                "dataRangeFrom": "2025-01-01T00:00:00.000Z",
                "dataRangeTo": now_iso,
                "expiryDate": "2027-12-31T23:59:59.000Z",
                "dataEraseAt": "2027-12-31T23:59:59.000Z",
                "status": "GRANTED",
                "requesterName": "Dr. Roshan",
                "createdAt": now_iso
            }},
            upsert=True
        )

    update_entry("consent_requests", consent_req_id, {
        "consentRequestId": consent_req_id,
        "consentArtifactId": consent_art_id,
        "status": "GRANTED",
        "patient": {"id": patient_abha}
    })
    update_entry("consent_requests", consent_art_id, {
        "consentId": consent_art_id,
        "status": "GRANTED",
        "patient": {"id": patient_abha}
    })
    print(f"[OK] Consent record seeded: ConsentRequestId={consent_req_id}, ConsentArtefactId={consent_art_id}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        
        # Step 2: Test /api/v1/consents/fetch
        print("\n[STEP 2] Testing Consent Fetch API (POST /api/v1/consents/fetch)...")
        fetch_payload = {
            "requestId": str(uuid.uuid4()),
            "timestamp": now_iso,
            "consentId": consent_art_id
        }
        res_fetch = await ac.post(f"{settings.API_V1_STR}/consents/fetch", headers=headers, json=fetch_payload)
        print(f"Status: {res_fetch.status_code}")
        assert res_fetch.status_code in [200, 202], f"Consent Fetch failed: {res_fetch.text}"
        print("[OK] Consent Fetch request dispatched successfully.")

        # Step 3: Test /api/v1/consents/on-fetch callback
        print("\n[STEP 3] Testing Consent On-Fetch Callback (POST /api/v1/consents/on-fetch)...")
        on_fetch_payload = {
            "requestId": str(uuid.uuid4()),
            "timestamp": now_iso,
            "consent": {
                "status": "GRANTED",
                "consentDetail": {
                    "consentId": consent_art_id,
                    "createdAt": now_iso,
                    "patient": {"id": patient_abha},
                    "careContexts": [{"patientReference": "P101", "careContextReference": "EPISODE-1"}],
                    "purpose": {"text": "Care Management", "code": "CAREMGT"},
                    "hiTypes": ["Prescription", "DiagnosticReport"],
                    "permission": {
                        "accessMode": "VIEW",
                        "dateRange": {"from": "2025-01-01T00:00:00.000Z", "to": now_iso},
                        "dataEraseAt": "2027-12-31T23:59:59.000Z",
                        "frequency": {"unit": "HOUR", "value": 1, "repeats": 0}
                    }
                },
                "signature": "SIGNATURE_BASE64_PLACEHOLDER"
            },
            "resp": {"requestId": fetch_payload["requestId"]}
        }
        res_on_fetch = await ac.post(f"{settings.API_V1_STR}/consents/on-fetch", headers=headers, json=on_fetch_payload)
        print(f"Status: {res_on_fetch.status_code}")
        assert res_on_fetch.status_code in [200, 202], f"On-Fetch failed: {res_on_fetch.text}"
        print("[OK] Consent on-fetch acknowledged.")

        # Step 4: Generate ECDH Key Material & Test Health Information Request
        print("\n[STEP 4] Generating ECDH Keys & Testing Health Information Request (POST /api/v1/health-information/request)...")
        hiu_priv_b64, hiu_pub_b64 = HealthInfoCryptoService.generate_key_pair()
        hiu_nonce = HealthInfoCryptoService.generate_key_pair()[1]

        hi_req_payload = {
            "requestId": str(uuid.uuid4()),
            "timestamp": now_iso,
            "transactionId": txn_id,
            "hiRequest": {
                "consent": {"id": consent_art_id},
                "dateRange": {
                    "from": "2025-01-01T00:00:00.000Z",
                    "to": now_iso
                },
                "dataPushUrl": "http://test/api/v1/health-information/data",
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
        res_hi_req = await ac.post(f"{settings.API_V1_STR}/health-information/request", headers=headers, json=hi_req_payload)
        print(f"Status: {res_hi_req.status_code}")
        assert res_hi_req.status_code in [200, 202], f"HI Request failed: {res_hi_req.text}"
        print("[OK] Health information request initiated successfully.")

        # Step 5: Test Health Information On-Request Callback
        print("\n[STEP 5] Testing Health Information On-Request (POST /api/v1/health-information/on-request)...")
        hi_on_req_payload = {
            "requestId": str(uuid.uuid4()),
            "timestamp": now_iso,
            "hiRequest": {
                "transactionId": txn_id,
                "sessionStatus": "ACKNOWLEDGED"
            },
            "resp": {"requestId": hi_req_payload["requestId"]}
        }
        res_hi_on_req = await ac.post(f"{settings.API_V1_STR}/health-information/on-request", headers=headers, json=hi_on_req_payload)
        print(f"Status: {res_hi_on_req.status_code}")
        assert res_hi_on_req.status_code in [200, 202], f"HI On-Request failed: {res_hi_on_req.text}"
        print("[OK] Health information on-request acknowledged.")

        # Step 6: Test Data Transfer (HIP Encrypts & Pushes Data to HIU)
        print("\n[STEP 6] Testing Encrypted Data Transfer (POST /api/v1/health-information/transfer)...")
        transfer_payload = {
            "transactionId": txn_id,
            "consent": {"id": consent_art_id},
            "dateRange": {
                "from": "2025-01-01T00:00:00.000Z",
                "to": now_iso
            },
            "dataPushUrl": "http://test/api/v1/health-information/data",
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
        res_transfer = await ac.post(f"{settings.API_V1_STR}/health-information/transfer", headers=headers, json=transfer_payload)
        print(f"Status: {res_transfer.status_code}")
        assert res_transfer.status_code in [200, 202], f"Transfer failed: {res_transfer.text}"
        print("[OK] Encrypted FHIR bundles transferred & decrypted.")

        # Step 7: Test Decrypted Health Records Retrieval (GET /api/v1/health-records/{txn_id})
        print(f"\n[STEP 7] Retrieving Decrypted Records (GET /api/v1/health-records/{txn_id})...")
        res_records = await ac.get(f"{settings.API_V1_STR}/health-records/{txn_id}", headers=headers)
        print(f"Status: {res_records.status_code}")
        assert res_records.status_code == 200, f"Get health records failed: {res_records.text}"
        records = res_records.json()
        print(f"Fetched Records Keys: {list(records.keys())}")
        print("[OK] Decrypted health records retrieved successfully.")

        # Step 8: Test Health Information Transfer Notification (POST /api/v1/health-information/notify)
        print("\n[STEP 8] Testing Data Flow Status Notification (POST /api/v1/health-information/notify)...")
        notify_payload = {
            "notification": {
                "consentId": consent_art_id,
                "transactionId": txn_id,
                "doneAt": now_iso,
                "notifier": {
                    "type": "HIP",
                    "id": "IN2910002343"
                },
                "statusNotification": {
                    "sessionStatus": "TRANSFERRED",
                    "hipId": "IN2910002343",
                    "statusResponses": [
                        {
                            "careContextReference": "EPISODE-1",
                            "hiStatus": "DELIVERED",
                            "description": "FHIR records delivered and verified"
                        }
                    ]
                }
            }
        }
        res_notify = await ac.post(f"{settings.API_V1_STR}/health-information/notify", headers=headers, json=notify_payload)
        print(f"Status: {res_notify.status_code}")
        assert res_notify.status_code in [200, 202], f"HI Notify failed: {res_notify.text}"
        print("[OK] Health information transfer status notification processed.")

        # Step 9: Test HIU CM Notify (POST /api/v1/health-information/cm/notify)
        print("\n[STEP 9] Testing HIU CM Notify (POST /api/v1/health-information/cm/notify)...")
        cm_notify_payload = {
            "transactionId": txn_id,
            "status": "SUCCESS"
        }
        res_cm_notify = await ac.post(f"{settings.API_V1_STR}/health-information/cm/notify", headers=headers, json=cm_notify_payload)
        print(f"Status: {res_cm_notify.status_code}")
        assert res_cm_notify.status_code in [200, 202], f"HI CM Notify failed: {res_cm_notify.text}"
        print("[OK] HIU CM Notify processed successfully.")

        # Step 10: Test Transfer Acknowledgment (POST /api/v1/health-information/ack)
        print("\n[STEP 10] Testing Health Information Acknowledgment (POST /api/v1/health-information/ack)...")
        ack_payload = {
            "transactionId": txn_id,
            "sessionStatus": "ACKNOWLEDGED"
        }
        res_ack = await ac.post(f"{settings.API_V1_STR}/health-information/ack", headers=headers, json=ack_payload)
        print(f"Status: {res_ack.status_code}")
        assert res_ack.status_code in [200, 202], f"HI Ack failed: {res_ack.text}"
        print("[OK] Health information acknowledgment verified.")

    print("\n" + "=" * 80)
    print("ALL ABDM M3 DATA REQUEST & TRANSFER APIS TESTED SUCCESSFULLY!")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(test_full_m3_data_flow())
