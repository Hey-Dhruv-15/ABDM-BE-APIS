"""Local JSON persistence for ABDM consent notifications."""
from __future__ import annotations

from typing import Any, Dict

from app.abdm.headers import utc_iso_timestamp
from app.abdm.json_storage import read_storage, get_entry, update_entry
from app.logging.logger import get_logger

logger = get_logger(__name__)


class ABDMConsentRepositoryError(Exception):
    """Raised when the ABDM consent registry is unavailable."""


class ABDMConsentRepository:
    """Stores consent state received from ABDM HIE-CM callbacks in local JSON."""

    def __init__(self) -> None:
        pass

    async def upsert_consent(
        self,
        *,
        consent_id: str,
        payload: Dict[str, Any],
        request_id: str,
        timestamp: str,
    ) -> Dict[str, Any]:
        if not consent_id.strip():
            raise ValueError("consentId is required")
        notification = payload.get("notification")
        if not isinstance(notification, dict):
            # Try parsing from raw payload if structured differently
            notification = payload

        patient = notification.get("patient") if isinstance(notification.get("patient"), dict) else {}
        status_val = notification.get("status") or payload.get("status") or "GRANTED"
        
        document = {
            "consentId": consent_id,
            "status": status_val,
            "transactionId": notification.get("transactionId"),
            "patient": patient,
            "hip": notification.get("hip") if isinstance(notification.get("hip"), dict) else {},
            "hiu": notification.get("hiu") if isinstance(notification.get("hiu"), dict) else {},
            "careContexts": notification.get("careContexts") or [],
            "purpose": notification.get("purpose") if isinstance(notification.get("purpose"), dict) else {},
            "permission": notification.get("permission") if isinstance(notification.get("permission"), dict) else {},
            "requestId": request_id,
            "timestamp": timestamp,
            "updatedAt": utc_iso_timestamp(),
            "raw": payload,
        }

        try:
            update_entry("consent_requests", consent_id, document)
        except Exception as exc:
            logger.error("JSON consent upsert failed", consent_id=consent_id, error=str(exc))
            raise ABDMConsentRepositoryError("JSON consent upsert failed") from exc

        logger.info(
            "JSON consent upsert completed",
            consent_id=consent_id,
            status=document.get("status"),
            patient_id=patient.get("id"),
            transaction_id=document.get("transactionId"),
        )
        return document

    async def find_by_consent_id(self, consent_id: str) -> Dict[str, Any] | None:
        clean_id = consent_id.strip()
        if not clean_id:
            return None
        try:
            document = get_entry("consent_requests", clean_id)
            if not document:
                all_consents = read_storage("consent_requests")
                for k, v in all_consents.items():
                    if isinstance(v, dict):
                        if (
                            k == clean_id
                            or v.get("consentArtifactId") == clean_id
                            or v.get("consentRequestId") == clean_id
                            or v.get("requestId") == clean_id
                            or v.get("consent", {}).get("id") == clean_id
                        ):
                            return v
        except Exception as exc:
            logger.error("JSON consent lookup failed", consent_id=consent_id, error=str(exc))
            raise ABDMConsentRepositoryError("JSON consent lookup failed") from exc
        return document


consent_repository = ABDMConsentRepository()
