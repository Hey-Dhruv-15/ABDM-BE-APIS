"""In-memory persistence for ABDM M3 Scan & Share patients."""
from __future__ import annotations

from typing import Any, Dict

from app.abdm.headers import utc_iso_timestamp
from app.logging.logger import get_logger

logger = get_logger(__name__)

# In-memory database for patient profiles
_patients_db: Dict[str, Dict[str, Any]] = {}


class ABDMM3PatientRepositoryError(Exception):
    """Raised when M3 patient persistence is unavailable."""


class ABDMM3PatientRepository:
    """Stores M3 profile-share patient registration state in memory."""

    def __init__(self) -> None:
        pass

    async def upsert_profile_share(
        self,
        *,
        abha_address: str,
        patient: Dict[str, Any],
        metadata: Dict[str, Any],
        request_id: str,
        token_number: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not abha_address.strip():
            raise ValueError("abhaAddress is required")

        document = {
            "abhaAddress": abha_address,
            "abhaNumber": patient.get("abhaNumber"),
            "name": patient.get("name"),
            "gender": patient.get("gender"),
            "dayOfBirth": patient.get("dayOfBirth"),
            "monthOfBirth": patient.get("monthOfBirth"),
            "yearOfBirth": patient.get("yearOfBirth"),
            "address": patient.get("address") if isinstance(patient.get("address"), dict) else {},
            "phoneNumber": patient.get("phoneNumber"),
            "hipId": metadata.get("hipId"),
            "context": metadata.get("context"),
            "hprId": metadata.get("hprId"),
            "latitude": metadata.get("latitude"),
            "longitude": metadata.get("longitude"),
            "status": "PROFILE_RECEIVED",
            "tokenNumber": token_number,
            "requestId": request_id,
            "updatedAt": utc_iso_timestamp(),
            "raw": payload,
        }

        _patients_db[abha_address] = document
        logger.info("In-memory M3 patient upsert completed", abha_address=abha_address)
        return document

    async def mark_registered(
        self,
        *,
        abha_address: str,
        context: str | None,
        token_number: str | None,
        expiry: int | str | None,
        request_id: str | None,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not abha_address.strip():
            raise ValueError("abhaAddress is required")

        update = {
            "status": "REGISTERED",
            "context": context,
            "tokenNumber": token_number,
            "expiry": expiry,
            "finalResponseRequestId": request_id,
            "finalCallback": payload,
            "updatedAt": utc_iso_timestamp(),
        }
        
        doc = _patients_db.get(abha_address, {})
        doc.update(update)
        _patients_db[abha_address] = doc
        
        logger.info("In-memory M3 patient registration update completed", abha_address=abha_address)
        return {
            "matchedCount": 1,
            "modifiedCount": 1,
            "upsertedId": "",
        }


m3_patient_repository = ABDMM3PatientRepository()
