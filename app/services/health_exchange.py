import os
import json
import uuid
import base64
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.settings import settings
from app.abdm.json_storage import update_entry, get_entry
from app.logging.logger import get_logger

logger = get_logger(__name__)


class HealthInfoCryptoService:
    @staticmethod
    def generate_key_pair() -> tuple[str, str]:
        """Generate ephemeral X25519 key pair (private_key_b64, public_key_b64)."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        pub_bytes = public_key.public_bytes_raw()
        priv_bytes = private_key.private_bytes_raw()
        
        pub_b64 = base64.b64encode(pub_bytes).decode('utf-8')
        priv_b64 = base64.b64encode(priv_bytes).decode('utf-8')
        
        return priv_b64, pub_b64

    @staticmethod
    def encrypt_data(fhir_bundle_str: str, peer_public_key_b64: str, my_private_key_b64: str, peer_nonce: str, my_nonce: str) -> str:
        """Encrypt FHIR bundle string using ECDH shared secret + AES-GCM (ABDM compliant)."""
        my_priv_bytes = base64.b64decode(my_private_key_b64.encode('utf-8'))
        peer_pub_bytes = base64.b64decode(peer_public_key_b64.encode('utf-8'))
        
        my_private_key = x25519.X25519PrivateKey.from_private_bytes(my_priv_bytes)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        
        # Compute ECDH shared secret
        shared_secret = my_private_key.exchange(peer_public_key)
        
        # Compute salt = my_nonce XOR peer_nonce
        my_nonce_bytes = base64.b64decode(my_nonce.encode('utf-8')) if len(my_nonce) > 16 else my_nonce.encode('utf-8')
        peer_nonce_bytes = base64.b64decode(peer_nonce.encode('utf-8')) if len(peer_nonce) > 16 else peer_nonce.encode('utf-8')
        
        max_len = max(len(my_nonce_bytes), len(peer_nonce_bytes))
        padded_my = my_nonce_bytes + b'\x00' * (max_len - len(my_nonce_bytes))
        padded_peer = peer_nonce_bytes + b'\x00' * (max_len - len(peer_nonce_bytes))
        salt = bytes(a ^ b for a, b in zip(padded_my, padded_peer))
        
        # Derivation: HKDF with SHA-256 for 32-byte AES key and 12-byte IV (total 44 bytes)
        hkdf = HKDF(
            algorithm=SHA256(),
            length=44,
            salt=salt,
            info=b"ABDM_HEALTH_INFORMATION_EXCHANGE",
            backend=None
        )
        key_material = hkdf.derive(shared_secret)
        aes_key = key_material[:32]
        iv = key_material[32:44]
        
        # AES-GCM encryption
        aesgcm = AESGCM(aes_key)
        encrypted_bytes = aesgcm.encrypt(iv, fhir_bundle_str.encode('utf-8'), None)
        
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    @staticmethod
    def decrypt_data(encrypted_data_b64: str, peer_public_key_b64: str, my_private_key_b64: str, peer_nonce: str, my_nonce: str) -> str:
        """Decrypt FHIR bundle using ECDH shared secret + AES-GCM (ABDM compliant)."""
        my_priv_bytes = base64.b64decode(my_private_key_b64.encode('utf-8'))
        peer_pub_bytes = base64.b64decode(peer_public_key_b64.encode('utf-8'))
        
        my_private_key = x25519.X25519PrivateKey.from_private_bytes(my_priv_bytes)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        
        shared_secret = my_private_key.exchange(peer_public_key)
        
        my_nonce_bytes = base64.b64decode(my_nonce.encode('utf-8')) if len(my_nonce) > 16 else my_nonce.encode('utf-8')
        peer_nonce_bytes = base64.b64decode(peer_nonce.encode('utf-8')) if len(peer_nonce) > 16 else peer_nonce.encode('utf-8')
        
        max_len = max(len(my_nonce_bytes), len(peer_nonce_bytes))
        padded_my = my_nonce_bytes + b'\x00' * (max_len - len(my_nonce_bytes))
        padded_peer = peer_nonce_bytes + b'\x00' * (max_len - len(peer_nonce_bytes))
        salt = bytes(a ^ b for a, b in zip(padded_my, padded_peer))
        
        hkdf = HKDF(
            algorithm=SHA256(),
            length=44,
            salt=salt,
            info=b"ABDM_HEALTH_INFORMATION_EXCHANGE",
            backend=None
        )
        key_material = hkdf.derive(shared_secret)
        aes_key = key_material[:32]
        iv = key_material[32:44]
        
        aesgcm = AESGCM(aes_key)
        encrypted_bytes = base64.b64decode(encrypted_data_b64.encode('utf-8'))
        decrypted_bytes = aesgcm.decrypt(iv, encrypted_bytes, None)
        
        return decrypted_bytes.decode('utf-8')


class FHIRBundleGenerator:
    @staticmethod
    def generate_bundle(hi_type: str, patient_id: str, care_context_ref: str) -> dict:
        """Generate a valid FHIR R4 Bundle for the specified record type."""
        now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        bundle_id = str(uuid.uuid4())
        hi_type_lower = hi_type.lower()
        
        # Resolve patient details dynamically from DB, JSON storage, or patient_id
        patient_name = None
        patient_gender = "other"
        patient_dob = "1990-01-01"
        patient_ref_id = patient_id or "REF001"
        practitioner_name = "Dr. Roshan"
        
        try:
            import re
            from app.db.mongo_manager import MongoDBManager
            db = MongoDBManager.get_db()
            if db is not None and patient_id:
                clean_pid = patient_id.strip()
                handle = clean_pid.split("@")[0]
                p_doc = db["patients"].find_one({
                    "$or": [
                        {"abha_address": clean_pid},
                        {"patient_id": clean_pid},
                        {"patient_reference": clean_pid},
                        {"abha_address": {"$regex": f"^{re.escape(handle)}", "$options": "i"}},
                    ]
                })
                if not p_doc:
                    p_doc = db["abdm_m3_patients"].find_one({
                        "$or": [
                            {"abhaAddress": clean_pid},
                            {"patientId": clean_pid},
                            {"id": clean_pid}
                        ]
                    })
                if p_doc:
                    patient_name = p_doc.get("full_name") or p_doc.get("name") or f"{p_doc.get('first_name', '')} {p_doc.get('last_name', '')}".strip()
                    gender_val = str(p_doc.get("gender") or "other").lower()
                    patient_gender = "female" if gender_val in ["f", "female"] else "male" if gender_val in ["m", "male"] else "other"
                    patient_dob = p_doc.get("date_of_birth") or p_doc.get("dob") or patient_dob
                    patient_ref_id = p_doc.get("patient_reference") or p_doc.get("patient_id") or clean_pid
        except Exception:
            pass

        # Check local JSON storage if MongoDB is not present or patient was not found in Mongo
        if not patient_name:
            try:
                from app.abdm.json_storage import read_storage
                clean_pid = (patient_id or "").strip()
                handle = clean_pid.split("@")[0] if "@" in clean_pid else clean_pid
                
                # Check consent_requests.json
                consent_records = read_storage("consent_requests")
                for c_val in consent_records.values():
                    if isinstance(c_val, dict):
                        p_info = c_val.get("patient") or {}
                        c_pat_id = p_info.get("id") or c_val.get("patientAbhaAddress") or c_val.get("patientId")
                        if c_pat_id and (
                            c_pat_id.lower() == clean_pid.lower()
                            or (handle and c_pat_id.lower().startswith(handle.lower()))
                        ):
                            patient_name = p_info.get("name") or c_val.get("patientName")
                            doc_req = c_val.get("consent", {}).get("requester", {}).get("name") or c_val.get("requesterName")
                            if doc_req:
                                practitioner_name = doc_req
                            break
                            
                # Check care_contexts.json
                if not patient_name:
                    care_records = read_storage("care_contexts")
                    for k, cc_val in care_records.items():
                        if isinstance(cc_val, dict):
                            cc_pat = cc_val.get("abhaAddress") or cc_val.get("patientId") or ""
                            if clean_pid and cc_pat and (
                                cc_pat.lower() == clean_pid.lower()
                                or (handle and cc_pat.lower().startswith(handle.lower()))
                            ):
                                patient_name = cc_val.get("patientName") or cc_val.get("patientDisplay")
                                break
            except Exception:
                pass
            
        if not patient_name or patient_name == "Patient":
            if patient_id and "@" in patient_id:
                patient_name = patient_id.split("@")[0].replace(".", " ").replace("_", " ").title()
            elif patient_id:
                patient_name = patient_id.replace(".", " ").replace("_", " ").title()
            else:
                patient_name = "Patient"

        patient_resource = {
            "resourceType": "Patient",
            "id": patient_ref_id,
            "name": [{"text": patient_name}],
            "gender": patient_gender,
            "birthDate": patient_dob
        }
        
        practitioner_resource = {
            "resourceType": "Practitioner",
            "id": "PRAC001",
            "name": [{"text": practitioner_name}]
        }
        
        encounter_resource = {
            "resourceType": "Encounter",
            "id": "ENC001",
            "status": "finished",
            "class": {
                "system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
                "code": "AMB",
                "display": "ambulatory"
            },
            "subject": {"reference": f"Patient/{patient_ref_id}"},
            "period": {"start": now_str, "end": now_str}
        }
        
        if "prescription" in hi_type_lower:
            composition = {
                "resourceType": "Composition",
                "id": "comp-presc",
                "status": "final",
                "type": {
                    "coding": [
                        {
                            "system": "http://loinc.org",
                            "code": "57833-6",
                            "display": "Prescription"
                        }
                    ]
                },
                "subject": {"reference": f"Patient/{patient_ref_id}"},
                "date": now_str,
                "author": [{"reference": "Practitioner/PRAC001"}],
                "title": "Prescription Document",
                "section": [
                    {
                        "title": "Medications",
                        "entry": [{"reference": "MedicationRequest/med-req-1"}]
                    }
                ]
            }
            
            med_request = {
                "resourceType": "MedicationRequest",
                "id": "med-req-1",
                "status": "active",
                "intent": "order",
                "medicationCodeableConcept": {
                    "text": "Paracetamol 500mg"
                },
                "subject": {"reference": f"Patient/{patient_ref_id}"},
                "authoredOn": now_str,
                "requester": {"reference": "Practitioner/PRAC001"}
            }
            
            entries = [
                {"fullUrl": f"Composition/comp-presc", "resource": composition},
                {"fullUrl": f"Patient/{patient_ref_id}", "resource": patient_resource},
                {"fullUrl": f"Practitioner/PRAC001", "resource": practitioner_resource},
                {"fullUrl": f"MedicationRequest/med-req-1", "resource": med_request}
            ]
            
        elif "diagnostic" in hi_type_lower:
            composition = {
                "resourceType": "Composition",
                "id": "comp-diag",
                "status": "final",
                "type": {
                    "coding": [
                        {
                            "system": "http://loinc.org",
                            "code": "11502-2",
                            "display": "Laboratory report"
                        }
                    ]
                },
                "subject": {"reference": f"Patient/{patient_ref_id}"},
                "date": now_str,
                "author": [{"reference": "Practitioner/PRAC001"}],
                "title": "Diagnostic Report Composition",
                "section": [
                    {
                        "title": "Lab Results",
                        "entry": [{"reference": "DiagnosticReport/diag-rep-1"}]
                    }
                ]
            }
            
            diag_report = {
                "resourceType": "DiagnosticReport",
                "id": "diag-rep-1",
                "status": "final",
                "code": {
                    "coding": [
                        {
                            "system": "http://loinc.org",
                            "code": "24331-1",
                            "display": "Lipid Profile"
                        }
                    ]
                },
                "subject": {"reference": f"Patient/{patient_ref_id}"},
                "conclusion": "Normal lipid profile",
                "result": [{"reference": "Observation/obs-1"}]
            }
            
            observation = {
                "resourceType": "Observation",
                "id": "obs-1",
                "status": "final",
                "code": {
                    "coding": [
                        {"system": "http://loinc.org", "code": "14647-2", "display": "Cholesterol [Mass/volume] in Serum or Plasma"}
                    ]
                },
                "subject": {"reference": f"Patient/{patient_ref_id}"},
                "valueQuantity": {
                    "value": 180,
                    "unit": "mg/dL",
                    "system": "http://unitsofmeasure.org",
                    "code": "mg/dL"
                }
            }
            
            entries = [
                {"fullUrl": f"Composition/comp-diag", "resource": composition},
                {"fullUrl": f"Patient/{patient_ref_id}", "resource": patient_resource},
                {"fullUrl": f"Practitioner/PRAC001", "resource": practitioner_resource},
                {"fullUrl": f"DiagnosticReport/diag-rep-1", "resource": diag_report},
                {"fullUrl": f"Observation/obs-1", "resource": observation}
            ]
            
        elif "discharge" in hi_type_lower:
            composition = {
                "resourceType": "Composition",
                "id": "comp-discharge",
                "status": "final",
                "type": {
                    "coding": [
                        {
                            "system": "http://loinc.org",
                            "code": "18842-5",
                            "display": "Discharge summary"
                        }
                    ]
                },
                "subject": {"reference": f"Patient/{patient_ref_id}"},
                "date": now_str,
                "author": [{"reference": "Practitioner/PRAC001"}],
                "title": "Discharge Summary Document",
                "section": [
                    {
                        "title": "Discharge Diagnosis",
                        "entry": [{"reference": "Condition/cond-1"}]
                    }
                ]
            }
            
            condition = {
                "resourceType": "Condition",
                "id": "cond-1",
                "clinicalStatus": {
                    "coding": [{"system": "http://terminology.hl7.org/CodeSystem/condition-clinical", "code": "resolved"}]
                },
                "code": {
                    "coding": [{"system": "http://snomed.info/sct", "code": "386661006", "display": "Fever of unknown origin"}]
                },
                "subject": {"reference": f"Patient/{patient_ref_id}"}
            }
            
            entries = [
                {"fullUrl": f"Composition/comp-discharge", "resource": composition},
                {"fullUrl": f"Patient/{patient_ref_id}", "resource": patient_resource},
                {"fullUrl": f"Practitioner/PRAC001", "resource": practitioner_resource},
                {"fullUrl": f"Encounter/ENC001", "resource": encounter_resource},
                {"fullUrl": f"Condition/cond-1", "resource": condition}
            ]
            
        elif "encounter" in hi_type_lower:
            location = {
                "resourceType": "Location",
                "id": "loc-1",
                "name": "Outpatient Ward"
            }
            encounter_resource["location"] = [{"location": {"reference": "Location/loc-1"}}]
            
            entries = [
                {"fullUrl": f"Patient/{patient_ref_id}", "resource": patient_resource},
                {"fullUrl": f"Encounter/ENC001", "resource": encounter_resource},
                {"fullUrl": f"Location/loc-1", "resource": location}
            ]
            
        else: # Default OP Consultation or others
            composition = {
                "resourceType": "Composition",
                "id": "comp-op",
                "status": "final",
                "type": {
                    "coding": [
                        {
                            "system": "http://loinc.org",
                            "code": "34108-1",
                            "display": "Outpatient Note"
                        }
                    ]
                },
                "subject": {"reference": f"Patient/{patient_ref_id}"},
                "date": now_str,
                "author": [{"reference": "Practitioner/PRAC001"}],
                "title": "OP Consultation Report",
                "section": [
                    {
                        "title": "Encounter Notes",
                        "entry": [{"reference": "Encounter/ENC001"}]
                    }
                ]
            }
            
            doc_ref = {
                "resourceType": "DocumentReference",
                "id": "doc-ref-1",
                "status": "current",
                "subject": {"reference": f"Patient/{patient_ref_id}"},
                "content": [
                    {
                        "attachment": {
                            "contentType": "text/plain",
                            "data": base64.b64encode(b"Patient consulted for routine health checkup.").decode("utf-8")
                        }
                    }
                ]
            }
            
            entries = [
                {"fullUrl": f"Composition/comp-op", "resource": composition},
                {"fullUrl": f"Patient/{patient_ref_id}", "resource": patient_resource},
                {"fullUrl": f"Practitioner/PRAC001", "resource": practitioner_resource},
                {"fullUrl": f"Encounter/ENC001", "resource": encounter_resource},
                {"fullUrl": f"DocumentReference/doc-ref-1", "resource": doc_ref}
            ]
            
        return {
            "resourceType": "Bundle",
            "id": bundle_id,
            "type": "document" if "encounter" not in hi_type_lower else "collection",
            "timestamp": now_str,
            "entry": entries
        }


class TransactionTracker:
    @staticmethod
    def create_transaction(
        transaction_id: str,
        consent_id: str,
        date_range: dict,
        data_push_url: str,
        peer_key_material: dict,
        my_private_key: str,
        my_public_key: str,
        my_nonce: str,
        care_contexts: list
    ) -> None:
        """Create a new transaction state record inside transactions.json."""
        document = {
            "transactionId": transaction_id,
            "consentId": consent_id,
            "dateRange": date_range,
            "dataPushUrl": data_push_url,
            "peerKeyMaterial": peer_key_material,
            "myKeyMaterial": {
                "privateKey": my_private_key,
                "publicKey": my_public_key,
                "nonce": my_nonce
            },
            "careContexts": care_contexts,
            "status": "REQUESTED",
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "auditLogs": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": "TRANSACTION_CREATED",
                    "details": f"HIE request initialized for consent {consent_id}"
                }
            ]
        }
        update_entry("transactions", transaction_id, document)
        logger.info("Transaction initialized in local storage", transaction_id=transaction_id)

    @staticmethod
    def update_status(transaction_id: str, status: str, error_message: str | None = None) -> None:
        """Update the status of an existing transaction."""
        txn = get_entry("transactions", transaction_id)
        if not txn:
            logger.warning("Transaction not found for status update", transaction_id=transaction_id)
            return
            
        txn["status"] = status
        txn["updatedAt"] = datetime.now(timezone.utc).isoformat()
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": f"STATUS_UPDATED_TO_{status}",
            "details": f"Transaction state changed to {status}"
        }
        if error_message:
            txn["error_message"] = error_message
            log_entry["details"] += f" with error: {error_message}"
            
        txn.setdefault("auditLogs", []).append(log_entry)
        update_entry("transactions", transaction_id, txn)
        logger.info("Transaction status updated", transaction_id=transaction_id, status=status)


class NotificationGenerator:
    @staticmethod
    def generate_notify_payload(transaction_id: str) -> dict:
        """Generate ABDM-compliant notify payload from stored transaction state."""
        txn = get_entry("transactions", transaction_id)
        if not txn:
            # Fallback mock payload if transaction doesn't exist
            return {
                "notification": {
                    "consentId": "consent-123",
                    "transactionId": transaction_id,
                    "doneAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "notifier": {
                        "type": "HIP",
                        "id": settings.ABDM_HIP_ID or "Hip_11"
                    },
                    "statusNotification": {
                        "sessionStatus": "TRANSFERRED",
                        "hipId": settings.ABDM_HIP_ID or "Hip_11",
                        "statusResponses": [
                            {
                                "careContextReference": "CC001",
                                "hiStatus": "DELIVERED",
                                "description": "FHIR data delivered successfully"
                            }
                        ]
                    }
                }
            }
            
        status = txn.get("status")
        consent_id = txn.get("consentId")
        
        session_status = "TRANSFERRED"
        hi_status = "DELIVERED"
        description = "FHIR data delivered successfully"
        
        if status == "FAILED":
            session_status = "FAILED"
            hi_status = "ERRORED"
            description = txn.get("error_message") or "Transfer failed"
            
        status_responses = []
        care_contexts = txn.get("careContexts") or [{"careContextReference": "CC001"}]
        for cc in care_contexts:
            ref = cc.get("careContextReference") or cc.get("referenceNumber") or "CC001"
            status_responses.append({
                "careContextReference": ref,
                "hiStatus": hi_status,
                "description": description
            })
            
        payload = {
            "notification": {
                "consentId": consent_id,
                "transactionId": transaction_id,
                "doneAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "notifier": {
                    "type": "HIP",
                    "id": settings.ABDM_HIP_ID or "Hip_11"
                },
                "statusNotification": {
                    "sessionStatus": session_status,
                    "hipId": settings.ABDM_HIP_ID or "Hip_11",
                    "statusResponses": status_responses
                }
            }
        }
        return payload
