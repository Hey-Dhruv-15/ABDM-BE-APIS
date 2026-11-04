"""Local JSON persistence for ABDM HIP linked care contexts."""
from __future__ import annotations

from typing import Any, Dict, List

from app.abdm.headers import utc_iso_timestamp
from app.abdm.json_storage import read_storage, update_entry
from app.logging.logger import get_logger
from app.settings import settings

logger = get_logger(__name__)


class ABDMLinkageRepositoryError(Exception):
    """Raised when the HIP linked care-context registry is unavailable."""


class ABDMLinkedCareContextRepository:
    """Stores HIP-side ABHA to linked care-context mappings in local JSON files."""

    def __init__(self) -> None:
        pass

    async def upsert_linkage(
        self,
        *,
        abha_address: str,
        abha_number: str,
        hip: Dict[str, Any],
        patient: List[Dict[str, Any]],
        request_id: str,
        linked_at: str | None = None,
    ) -> Dict[str, Any]:
        """Insert or update the linked care-context document for an ABHA address."""
        if not abha_address.strip():
            raise ValueError("abhaAddress is required")
        if not patient or not _has_care_contexts(patient):
            raise ValueError("patient careContexts cannot be empty")

        # Save to care_contexts.json with composite keys to prevent cross-patient reference collision
        for entry in patient:
            pat_ref = entry.get("referenceNumber") or "REF001"
            hi_type = entry.get("hiType") or "Prescription"
            care_contexts = entry.get("careContexts") or []
            for cc in care_contexts:
                cc_ref = cc.get("referenceNumber")
                cc_display = cc.get("display") or entry.get("display") or "OPD Consultation"
                if cc_ref:
                    composite_key = f"{abha_address}:{cc_ref}"
                    update_entry("care_contexts", composite_key, {
                        "abhaAddress": abha_address,
                        "referenceNumber": pat_ref,
                        "hiType": hi_type,
                        "display": cc_display,
                        "patientDisplay": entry.get("display") or "Visit Details"
                    })

        document = {
            "abhaAddress": abha_address,
            "abhaNumber": str(abha_number),
            "hip": {
                "id": str(hip.get("id") or ""),
                "name": str(hip.get("name") or hip.get("id") or ""),
                "type": str(hip.get("type") or "HIP"),
            },
            "patient": patient,
            "linkedAt": linked_at or utc_iso_timestamp(),
            "requestId": request_id,
        }

        logger.info(
            "JSON linked care-context upsert completed",
            abha_address=abha_address,
        )
        return document

    async def find_by_abha_address(self, abha_address: str) -> Dict[str, Any] | None:
        """Fetch the linked care-context document for an ABHA address."""
        if not abha_address.strip():
            raise ValueError("abhaAddress is required")

        all_contexts = read_storage("care_contexts")
        matched_contexts = {}
        for composite_key, val in all_contexts.items():
            if isinstance(val, dict) and val.get("abhaAddress") == abha_address:
                # Extract clean care context reference
                cc_ref = composite_key.split(":")[-1]
                matched_contexts[cc_ref] = val

        if not matched_contexts:
            logger.info(
                "JSON linked care-context lookup completed",
                abha_address=abha_address,
                found=False,
            )
            return None

        # Reconstruct MongoDB-like patient schema
        patients_map: Dict[str, Dict[str, Any]] = {}
        for cc_ref, val in matched_contexts.items():
            pat_ref = val.get("referenceNumber") or "REF001"
            hi_type = val.get("hiType") or "Prescription"
            display = val.get("display") or "OPD Consultation"
            pat_display = val.get("patientDisplay") or "Visit Details"

            if pat_ref not in patients_map:
                patients_map[pat_ref] = {
                    "referenceNumber": pat_ref,
                    "display": pat_display,
                    "hiType": hi_type,
                    "careContexts": []
                }
            patients_map[pat_ref]["careContexts"].append({
                "referenceNumber": cc_ref,
                "display": display
            })

        normalized = {
            "abhaAddress": abha_address,
            "abhaNumber": "",
            "hip": {
                "id": settings.ABDM_HIP_ID or "HIP_11",
                "name": settings.ABDM_HIP_ID or "HIP_11",
                "type": "HIP",
            },
            "patient": list(patients_map.values()),
            "linkedAt": utc_iso_timestamp(),
            "requestId": "mock-req-id",
        }

        logger.info(
            "JSON linked care-context lookup completed",
            abha_address=abha_address,
            found=True,
        )
        return normalized


def _has_care_contexts(patient: List[Dict[str, Any]]) -> bool:
    for entry in patient:
        care_contexts = entry.get("careContexts") if isinstance(entry, dict) else None
        if isinstance(care_contexts, list) and care_contexts:
            return True
    return False


linked_care_context_repository = ABDMLinkedCareContextRepository()
