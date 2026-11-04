"""Header utilities for outbound ABDM requests."""
from datetime import datetime, timezone
from typing import Dict
from uuid import uuid4


def utc_iso_timestamp() -> str:
    """Return UTC timestamp in ISO-8601 format expected by ABDM headers."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_abdm_headers(
    access_token: str,
    cm_id: str,
    region: str = "india",
    integration: str = "test-relay",
    participant_id: str = "",
    participant_type: str = "HIP",
) -> Dict[str, str]:
    """Build standard ABDM gateway headers for all outbound calls."""
    headers: Dict[str, str] = {
        "Authorization": f"Bearer {access_token}",
        "X-CM-ID": cm_id,
        "X-Region": region,
        "X-Integration": integration,
        "REQUEST-ID": str(uuid4()),
        "TIMESTAMP": utc_iso_timestamp(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    normalized_type = participant_type.strip().upper()
    if participant_id:
        participant_header = "X-HIP-ID" if normalized_type == "HIP" else "X-HIU-ID"
        headers[participant_header] = participant_id

    return headers


def generateRequestId() -> str:
    """Generate dynamic UUID v4 for REQUEST-ID."""
    return str(uuid4())


def generateTimestamp() -> str:
    """Generate dynamic ISO-8601 UTC timestamp for TIMESTAMP."""
    return utc_iso_timestamp()


def generateCorrelationId() -> str:
    """Generate dynamic UUID v4 for X-Correlation-ID."""
    return str(uuid4())


def buildABDMHeaders(
    access_token: str,
    cm_id: str = "sbx",
    region: str = "india",
    integration: str = "test-relay",
    correlation_id: str | None = None,
    request_id: str | None = None,
    timestamp: str | None = None,
    participant_id: str | None = None,
    participant_type: str | None = None,
) -> Dict[str, str]:
    """Build standard dynamic headers for Milestone 3 API requests."""
    headers = {
        "Authorization": f"Bearer {access_token}" if access_token else "",
        "REQUEST-ID": request_id or generateRequestId(),
        "TIMESTAMP": timestamp or generateTimestamp(),
        "X-CM-ID": cm_id,
        "X-Region": region,
        "X-Integration": integration,
        "X-Correlation-ID": correlation_id or generateCorrelationId(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if not headers["Authorization"]:
        headers.pop("Authorization", None)

    if participant_id:
        normalized_type = (participant_type or "HIP").strip().upper()
        participant_header = "X-HIP-ID" if normalized_type == "HIP" else "X-HIU-ID"
        headers[participant_header] = participant_id

    return headers
