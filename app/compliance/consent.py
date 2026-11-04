"""Consent policy checks for gateway operations."""
from dataclasses import dataclass

from fastapi import HTTPException, status


@dataclass
class PatientSearchPolicyInput:
    """Input contract for patient-search consent policy checks."""

    network: str
    consent_id: str | None
    purpose: str | None


def enforce_patient_search_consent(payload: PatientSearchPolicyInput) -> None:
    """Apply consent and purpose checks per health network."""
    network = payload.network.strip().upper()
    if not payload.purpose:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="purpose is required for patient search",
        )

    # ABHA health-information access must be consent-driven.
    if network == "ABHA" and not payload.consent_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="consent_id is required for ABHA patient search",
        )

