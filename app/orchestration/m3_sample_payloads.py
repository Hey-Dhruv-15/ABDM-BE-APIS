"""
Sample payload templates for ABDM Milestone 3 (Consent Management & Health Information Exchange).
Derived directly from official ABDM Sandbox Documentation Version 2.6.

IMPORTANT: This module is isolated for M3 usage only and does NOT alter any M1 or M2 logic.
"""

from typing import Dict, Any
from uuid import uuid4
from datetime import datetime, timezone

def get_m3_consent_init_sample_payload(
    patient_id: str = "patient@sbx",
    hiu_id: str = "IN2910002345",
    hip_id: str = "IN2910002345"
) -> Dict[str, Any]:
    """Sample payload for POST /api/hiecm/consent/v3/request/init (Doc Section 4.3.1)."""
    return {
        "consent": {
            "purpose": {
                "text": "Care Management",
                "code": "CAREMGT",
                "refUri": "https://www.abdm.gov.in"
            },
            "patient": {
                "id": patient_id
            },
            "hip": {
                "id": hip_id
            },
            "hiu": {
                "id": hiu_id
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
                "DischargeSummary",
                "OPConsultation"
            ],
            "permission": {
                "accessMode": "VIEW",
                "dateRange": {
                    "from": "2024-01-01T00:00:00.000Z",
                    "to": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                },
                "dataEraseAt": "2026-12-31T23:59:59.000Z",
                "frequency": {
                    "unit": "HOUR",
                    "value": 1,
                    "repeats": 0
                }
            }
        }
    }

def get_m3_consent_fetch_sample_payload(consent_id: str | None = None) -> Dict[str, Any]:
    """Sample payload for POST /api/hiecm/consent/v3/fetch (Doc Section 4.3.7)."""
    return {
        "consentId": consent_id or str(uuid4())
    }

def get_m3_health_info_request_sample_payload(
    consent_id: str | None = None,
    data_push_url: str = "http://127.0.0.1:8000/api/v1/health-information/transfer"
) -> Dict[str, Any]:
    """Sample payload for POST /api/hiecm/data-flow/v3/health-information/request (Doc Section 5.3.1)."""
    return {
        "hiRequest": {
            "consent": {
                "id": consent_id or "004ff8e6-a9d7-4963-822b-d9762179314e"
            },
            "dateRange": {
                "from": "2024-01-01T00:00:00.000Z",
                "to": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            },
            "dataPushUrl": data_push_url,
            "keyMaterial": {
                "cryptoAlg": "ECDH",
                "curve": "Curve25519",
                "dhPublicKey": {
                    "expiry": "2026-12-31T00:00:00.000Z",
                    "parameters": "Curve25519/32byte random key",
                    "keyValue": "BCpsBW37KgfLyjxJK0zHHG26hDjxzK368DEO4PapzFhQM0cghZziKuvJh5/anTnHitVHKMn0Owr1HvcH1fm0D pA="
                },
                "nonce": "0ka0stPfqmXWhX+ODC/iOFMO0PXFdRjBdcEGbv55qqc="
            }
        }
    }

def get_m3_health_info_notify_sample_payload(
    consent_id: str | None = None,
    transaction_id: str | None = None,
    hiu_id: str = "IN2910002345",
    hip_id: str = "IN2910002345"
) -> Dict[str, Any]:
    """Sample payload for POST /api/hiecm/data-flow/v3/health-information/notify (Doc Section 5.3.3)."""
    c_id = consent_id or str(uuid4())
    t_id = transaction_id or str(uuid4())
    return {
        "notification": {
            "consentId": c_id,
            "transactionId": t_id,
            "doneAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "notifier": {
                "type": "HIU",
                "id": hiu_id
            },
            "statusNotification": {
                "sessionStatus": "TRANSFERRED",
                "hipId": hip_id,
                "statusResponses": [
                    {
                        "careContextReference": "EPISODE-001",
                        "hiStatus": "OK",
                        "description": "Care Management"
                    }
                ]
            }
        }
    }
