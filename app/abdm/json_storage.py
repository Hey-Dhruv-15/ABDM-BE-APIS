"""Thread-safe JSON file storage utility for ABDM certification with seed data and reset capability."""
import os
import json
import threading
from typing import Any, Dict

_file_lock = threading.RLock()

# Store files in the root directory (Gateway/)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

PATHS = {
    "link_tokens": os.path.join(BASE_DIR, "link_tokens.json"),
    "care_contexts": os.path.join(BASE_DIR, "care_contexts.json"),
    "consent_requests": os.path.join(BASE_DIR, "consent_requests.json"),
    "health_records": os.path.join(BASE_DIR, "health_records.json"),
    "transactions": os.path.join(BASE_DIR, "transactions.json"),
}

def init_storage() -> None:
    """Ensure all JSON storage files exist and are initialized with default/seed objects."""
    with _file_lock:
        # Initialize link_tokens.json with seed data
        tokens_path = PATHS["link_tokens"]
        if not os.path.exists(tokens_path) or os.path.getsize(tokens_path) == 0:
            try:
                seed_tokens = {
                    "patient@sbx": {"linkToken": "mock-link-token"},
                    "patient@abdm": {"linkToken": "mock-link-token"}
                }
                with open(tokens_path, "w", encoding="utf-8") as f:
                    json.dump(seed_tokens, f, indent=2)
            except Exception:
                pass

        # Initialize care_contexts.json with seed data using composite keys
        contexts_path = PATHS["care_contexts"]
        if not os.path.exists(contexts_path) or os.path.getsize(contexts_path) == 0:
            try:
                seed_contexts = {
                    "patient@sbx:CC001": {
                        "abhaAddress": "patient@sbx",
                        "referenceNumber": "REF001",
                        "hiType": "Prescription",
                        "display": "Prescription",
                        "patientDisplay": "Visit 1"
                    },
                    "patient@abdm:CC001": {
                        "abhaAddress": "patient@abdm",
                        "referenceNumber": "REF001",
                        "hiType": "Prescription",
                        "display": "Prescription",
                        "patientDisplay": "Visit 1"
                    }
                }
                with open(contexts_path, "w", encoding="utf-8") as f:
                    json.dump(seed_contexts, f, indent=2)
            except Exception:
                pass

        # Initialize consent_requests.json with seed data
        consent_path = PATHS["consent_requests"]
        if not os.path.exists(consent_path) or os.path.getsize(consent_path) == 0:
            try:
                seed_consents = {
                    "CONS-2026-001": {
                        "requestId": "CONS-2026-001",
                        "consentRequestId": "CONS-2026-001",
                        "consentArtifactId": "CONSENT-ART-88191",
                        "status": "GRANTED",
                        "patient": {
                            "id": "sroshan110707@sbx",
                            "name": "Roshan S"
                        },
                        "patientAbhaAddress": "sroshan110707@sbx",
                        "patientName": "Roshan S",
                        "requesterName": "Dr. Roshan S",
                        "consent": {
                            "id": "CONSENT-ART-88191",
                            "purpose": {"text": "Care Management", "code": "CAREMGT"},
                            "patient": {"id": "sroshan110707@sbx", "name": "Roshan S"},
                            "hiTypes": ["Prescription", "DiagnosticReport", "OPConsultation"],
                            "requester": {"name": "Dr. Roshan S", "identifier": {"type": "REGNO1", "value": "MH1001"}},
                            "permission": {
                                "accessMode": "VIEW",
                                "dateRange": {"from": "2025-01-01T00:00:00.000Z", "to": "2026-09-02T23:59:59.000Z"},
                                "dataEraseAt": "2027-06-19T09:00:00.000Z"
                            }
                        },
                        "hiTypes": ["Prescription", "DiagnosticReport", "OPConsultation"],
                        "dataRangeFrom": "2025-01-01T00:00:00.000Z",
                        "dataRangeTo": "2026-09-02T23:59:59.000Z",
                        "expiryDate": "2026-12-31T23:59:59.000Z",
                        "dataEraseAt": "2027-06-19T09:00:00.000Z",
                        "createdAt": "2026-08-21T12:00:00.000Z",
                        "timestamp": "2026-08-21T12:00:00.000Z"
                    },
                    "CONS-2026-002": {
                        "requestId": "CONS-2026-002",
                        "consentRequestId": "CONS-2026-002",
                        "consentArtifactId": "CONSENT-ART-99202",
                        "status": "GRANTED",
                        "patient": {
                            "id": "rahul.m@sbx",
                            "name": "Rahul M"
                        },
                        "patientAbhaAddress": "rahul.m@sbx",
                        "patientName": "Rahul M",
                        "requesterName": "Dr. Anjali Nair",
                        "consent": {
                            "id": "CONSENT-ART-99202",
                            "purpose": {"text": "Care Management", "code": "CAREMGT"},
                            "patient": {"id": "rahul.m@sbx", "name": "Rahul M"},
                            "hiTypes": ["DiagnosticReport", "WellnessRecord"],
                            "requester": {"name": "Dr. Anjali Nair", "identifier": {"type": "REGNO2", "value": "MH1002"}},
                            "permission": {
                                "accessMode": "STORE",
                                "dateRange": {"from": "2025-06-01T00:00:00.000Z", "to": "2026-09-01T23:59:59.000Z"},
                                "dataEraseAt": "2027-05-15T09:00:00.000Z"
                            }
                        },
                        "hiTypes": ["DiagnosticReport", "WellnessRecord"],
                        "dataRangeFrom": "2025-06-01T00:00:00.000Z",
                        "dataRangeTo": "2026-09-01T23:59:59.000Z",
                        "expiryDate": "2026-11-30T23:59:59.000Z",
                        "dataEraseAt": "2027-05-15T09:00:00.000Z",
                        "createdAt": "2026-08-22T14:30:00.000Z",
                        "timestamp": "2026-08-22T14:30:00.000Z"
                    },
                    "CONS-2026-003": {
                        "requestId": "CONS-2026-003",
                        "consentRequestId": "CONS-2026-003",
                        "consentArtifactId": "-",
                        "status": "REQUESTED",
                        "patient": {
                            "id": "patient@sbx",
                            "name": "John Doe"
                        },
                        "patientAbhaAddress": "patient@sbx",
                        "patientName": "John Doe",
                        "requesterName": "Dr. Roshan S",
                        "consent": {
                            "purpose": {"text": "Treatment", "code": "CAREMGT"},
                            "patient": {"id": "patient@sbx", "name": "John Doe"},
                            "hiTypes": ["Prescription", "DischargeSummary"],
                            "requester": {"name": "Dr. Roshan S"},
                            "permission": {
                                "accessMode": "VIEW",
                                "dateRange": {"from": "2025-01-01T00:00:00.000Z", "to": "2026-08-30T23:59:59.000Z"},
                                "dataEraseAt": "2027-04-30T09:00:00.000Z"
                            }
                        },
                        "hiTypes": ["Prescription", "DischargeSummary"],
                        "dataRangeFrom": "2025-01-01T00:00:00.000Z",
                        "dataRangeTo": "2026-08-30T23:59:59.000Z",
                        "expiryDate": "2026-10-31T23:59:59.000Z",
                        "dataEraseAt": "2027-04-30T09:00:00.000Z",
                        "createdAt": "2026-08-23T09:15:00.000Z",
                        "timestamp": "2026-08-23T09:15:00.000Z"
                    }
                }
                with open(consent_path, "w", encoding="utf-8") as f:
                    json.dump(seed_consents, f, indent=2)
            except Exception:
                pass

        # Initialize remaining files
        for key in ["health_records", "transactions"]:
            path = PATHS[key]
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump({}, f, indent=2)
                except Exception:
                    pass

def reset_json_storage() -> None:
    """Clear all JSON storage files and re-initialize them with seed data."""
    with _file_lock:
        for path in PATHS.values():
            if os.path.exists(path):
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump({}, f)
                except Exception:
                    pass
        init_storage()

def read_storage(key: str) -> Dict[str, Any]:
    """Read a specific JSON file storage."""
    init_storage()
    path = PATHS.get(key)
    if not path:
        raise ValueError(f"Unknown storage key: {key}")
    with _file_lock:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

def write_storage(key: str, data: Dict[str, Any]) -> None:
    """Overwrite a specific JSON file storage safely handling Docker bind mounts."""
    init_storage()
    path = PATHS.get(key)
    if not path:
        raise ValueError(f"Unknown storage key: {key}")
    with _file_lock:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
        except Exception as exc:
            raise exc

def update_entry(key: str, entry_id: str, value: Any) -> None:
    """Update a specific entry in a JSON file storage, merging dict values if existing is a dict."""
    with _file_lock:
        data = read_storage(key)
        if isinstance(value, dict) and isinstance(data.get(entry_id), dict):
            merged = dict(data[entry_id])
            for k, v in value.items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    inner = dict(merged[k])
                    inner.update(v)
                    merged[k] = inner
                else:
                    merged[k] = v
            data[entry_id] = merged
        else:
            data[entry_id] = value
        write_storage(key, data)

def get_entry(key: str, entry_id: str) -> Any | None:
    """Get a specific entry from a JSON file storage."""
    with _file_lock:
        data = read_storage(key)
        return data.get(entry_id)
