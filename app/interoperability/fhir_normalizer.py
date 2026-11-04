"""FHIR resource normalization helpers for canonical gateway responses."""
from __future__ import annotations

from typing import Any, Dict


def normalize_fhir_resource(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize common FHIR resources into compact canonical structures."""
    resource_type = (resource.get("resourceType") or "").strip()
    if resource_type == "Patient":
        return _normalize_patient(resource)
    if resource_type == "Observation":
        return _normalize_observation(resource)
    if resource_type == "Encounter":
        return _normalize_encounter(resource)
    if resource_type in {"Medication", "MedicationRequest"}:
        return _normalize_medication(resource)
    return {"resource_type": resource_type or "Unknown", "raw": resource}


def _normalize_patient(resource: Dict[str, Any]) -> Dict[str, Any]:
    names = resource.get("name") or []
    primary_name = names[0] if names else {}
    given = primary_name.get("given") or []
    full_name = primary_name.get("text") or " ".join([*given, primary_name.get("family", "")]).strip()
    return {
        "resource_type": "Patient",
        "patient_id": resource.get("id"),
        "name": full_name or None,
        "gender": resource.get("gender"),
        "dob": resource.get("birthDate"),
    }


def _normalize_observation(resource: Dict[str, Any]) -> Dict[str, Any]:
    code = ((resource.get("code") or {}).get("text")) or None
    value_quantity = resource.get("valueQuantity") or {}
    value = value_quantity.get("value")
    unit = value_quantity.get("unit")
    return {
        "resource_type": "Observation",
        "observation_id": resource.get("id"),
        "code": code,
        "value": value,
        "unit": unit,
        "effective_at": resource.get("effectiveDateTime"),
    }


def _normalize_encounter(resource: Dict[str, Any]) -> Dict[str, Any]:
    period = resource.get("period") or {}
    return {
        "resource_type": "Encounter",
        "encounter_id": resource.get("id"),
        "status": resource.get("status"),
        "start": period.get("start"),
        "end": period.get("end"),
    }


def _normalize_medication(resource: Dict[str, Any]) -> Dict[str, Any]:
    med_text = None
    med_codeable = resource.get("medicationCodeableConcept") or resource.get("code") or {}
    if isinstance(med_codeable, dict):
        med_text = med_codeable.get("text")
    return {
        "resource_type": resource.get("resourceType"),
        "medication_id": resource.get("id"),
        "name": med_text,
        "status": resource.get("status"),
    }

