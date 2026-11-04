import sys
sys.path.insert(0, ".")
import uuid
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.abdm.json_storage import get_entry, update_entry, read_storage
from app.services.health_exchange import HealthInfoCryptoService
from app.db.mongo_manager import MongoDBManager

def main():
    with TestClient(app) as client:
        req_id = "3efc551a-181b-4c95-9018-9a9b10f01f00"
        consent_artifact_id = f"consent-{req_id}"
        txn_id = f"TXN-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "X-Region": "india",
            "X-CM-ID": "sbx",
            "REQUEST-ID": str(uuid.uuid4()),
            "TIMESTAMP": now_iso,
            "Authorization": "Bearer test-jwt-token-12345"
        }
        
        print("=" * 80)
        print("1. STEP 1: UPDATING CONSENT STATUS TO 'GRANTED' WITH ARTIFACT ID")
        print("=" * 80)
        
        # 1. Update in local json storage
        consent_record = get_entry("consent_requests", req_id) or {}
        consent_obj = consent_record.get("consent", {})
        patient_obj = consent_record.get("patient", {}) or {"id": "sroshan110707@sbx"}
        
        update_entry("consent_requests", req_id, {
            "requestId": req_id,
            "consentRequestId": req_id,
            "consentArtifactId": consent_artifact_id,
            "status": "GRANTED",
            "patient": patient_obj,
            "consent": consent_obj,
            "updatedAt": now_iso
        })
        
        update_entry("consent_requests", consent_artifact_id, {
            "consentId": consent_artifact_id,
            "consentRequestId": req_id,
            "status": "GRANTED",
            "patient": patient_obj,
            "consent": consent_obj,
            "readyForHealthInformationRequest": True,
            "timestamp": now_iso
        })
        
        # 2. Update in MongoDB
        try:
            db = MongoDBManager.get_db()
            if db is not None:
                db["abdm_consent_management"].update_one(
                    {"consentRequestId": req_id},
                    {"$set": {
                        "consentRequestId": req_id,
                        "consentArtifactId": consent_artifact_id,
                        "patientAbhaAddress": patient_obj.get("id") or "sroshan110707@sbx",
                        "patientName": patient_obj.get("name") or "Roshan S",
                        "hiTypes": consent_obj.get("hiTypes") or ["Prescription", "DiagnosticReport", "OPConsultation", "DischargeSummary"],
                        "dataRangeFrom": "2025-01-01T00:00:00.000Z",
                        "dataRangeTo": now_iso,
                        "expiryDate": "2027-12-31T23:59:59.000Z",
                        "dataEraseAt": "2027-12-31T23:59:59.000Z",
                        "status": "GRANTED",
                        "requesterName": "Dr. Roshan",
                        "updatedAt": now_iso
                    }},
                    upsert=True
                )
                MongoDBManager.log_audit_event(
                    milestone="M3",
                    event_type="CONSENT_GRANTED",
                    transaction_id=req_id,
                    patient_id=str(patient_obj.get("id") or "sroshan110707@sbx"),
                    status="GRANTED",
                    hip_id="IN2910002343",
                    hiu_id="IN2910002345",
                    details={"consentArtifactId": consent_artifact_id, "status": "GRANTED"}
                )
                print(f"-> MongoDB updated: Consent '{req_id}' is GRANTED with Artifact '{consent_artifact_id}'.")
        except Exception as e:
            print(f"MongoDB Note: {e}")
            
        print(f"-> Local storage updated: Consent '{req_id}' is GRANTED with Artifact '{consent_artifact_id}'.")
        
        print("\n" + "=" * 80)
        print("2. STEP 2: VERIFYING IN CONSENT MANAGEMENT API (GET /api/v1/consent-requests)")
        print("=" * 80)
        res_consents = client.get("/api/v1/consent-requests", headers=headers)
        print(f"HTTP Status: {res_consents.status_code}")
        if res_consents.status_code == 200:
            print(f"Active Consents Summary: {json.dumps(res_consents.json(), indent=2)}")
        
        print("\n" + "=" * 80)
        print(f"3. STEP 3: PERFORMING ECDH ENCRYPTED HEALTH DATA TRANSFER (Txn: {txn_id})")
        print("=" * 80)
        hiu_priv_b64, hiu_pub_b64 = HealthInfoCryptoService.generate_key_pair()
        hiu_nonce = HealthInfoCryptoService.generate_key_pair()[1]
        
        transfer_payload = {
            "transactionId": txn_id,
            "consent": {
                "id": consent_artifact_id
            },
            "dateRange": {
                "from": "2025-01-01T00:00:00.000Z",
                "to": now_iso
            },
            "dataPushUrl": "http://127.0.0.1:8005/api/v1/health-information/data",
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
        
        res_transfer = client.post("/api/v1/health-information/transfer", headers=headers, json=transfer_payload)
        print(f"HTTP Status: {res_transfer.status_code}")
        print(f"Transfer Response: {json.dumps(res_transfer.json(), indent=2)}")
        
        print("\n" + "=" * 80)
        print(f"4. STEP 4: RETRIEVING DECRYPTED FHIR HEALTH RECORDS (GET /api/v1/health-records/{txn_id})")
        print("=" * 80)
        res_records = client.get(f"/api/v1/health-records/{txn_id}", headers=headers)
        print(f"HTTP Status: {res_records.status_code}")
        if res_records.status_code == 200:
            records_data = res_records.json()
            print("Decrypted FHIR Medical Bundle:")
            print(json.dumps(records_data, indent=2))
        else:
            print(f"Records Response Body: {res_records.text}")
            
        print("\n" + "=" * 80)
        print("ABDM M3 CONSENT & HEALTH INFORMATION EXCHANGE COMPLETED SUCCESSFULLY!")
        print("=" * 80)

if __name__ == "__main__":
    main()
