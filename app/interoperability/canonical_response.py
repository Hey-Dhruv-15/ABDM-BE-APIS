"""Canonical response builders for multi-network operations."""
from typing import Any, Dict


def build_gateway_response(
    *,
    correlation_id: str,
    region: str | None,
    network: str | None,
    status: str,
    data: Dict[str, Any],
    upstream: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Create a normalized response envelope for gateway APIs."""
    return {
        "status": status,
        "correlation_id": correlation_id,
        "region": region,
        "network": network,
        "data": data,
        "upstream": upstream or {},
    }


def canonicalize_nabidh_patient(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Map FHIR Patient resource into a compact canonical patient shape."""
    names = resource.get("name") or []
    primary_name = names[0] if names else {}
    given = primary_name.get("given") or []
    full_name = primary_name.get("text") or " ".join([*given, primary_name.get("family", "")]).strip()

    return {
        "patient_id": resource.get("id"),
        "name": full_name or None,
        "gender": resource.get("gender"),
        "dob": resource.get("birthDate"),
        "source_format": resource.get("resourceType"),
    }

