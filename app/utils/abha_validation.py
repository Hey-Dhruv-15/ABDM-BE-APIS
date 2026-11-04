"""Validation helpers for ABHA-specific request fields."""
from __future__ import annotations

from datetime import datetime
from typing import Dict
from urllib.parse import urlparse

from fastapi import HTTPException, status

DEFAULT_DATE_FROM = "2024-01-01T00:00:00Z"
DEFAULT_DATE_TO = "2026-01-01T00:00:00Z"


def normalize_abha_number(value: str) -> str:
    """Normalize ABHA number to 14 digits and reject malformed identifiers."""
    candidate = (value or "").strip()
    compact = candidate.replace("-", "").replace(" ", "")
    if not compact.isdigit() or len(compact) != 14:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ABHA number must be 14 digits (hyphens/spaces allowed).",
        )
    return compact


def validate_consent_id(value: str | None) -> str:
    """Validate consent id for safe path interpolation and upstream forwarding."""
    consent_id = (value or "").strip()
    if not consent_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="consent_id is required for ABHA")
    if len(consent_id) > 256:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="consent_id is too long")
    if "/" in consent_id or "\\" in consent_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="consent_id contains invalid path characters",
        )
    return consent_id


def validate_data_push_url(value: str | None) -> str | None:
    """Allow only absolute HTTPS callback URLs for ABHA async data push."""
    if value is None:
        return None
    url = value.strip()
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="data_push_url must be an absolute https URL",
        )
    return url


def build_validated_date_range(date_from: str | None, date_to: str | None) -> Dict[str, str]:
    """Return a validated ABHA dateRange object with sane defaults."""
    start = _parse_iso8601(date_from or DEFAULT_DATE_FROM, field_name="date_from")
    end = _parse_iso8601(date_to or DEFAULT_DATE_TO, field_name="date_to")
    if start > end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="date_from must be before or equal to date_to",
        )
    return {"from": _format_iso8601(start), "to": _format_iso8601(end)}


def _parse_iso8601(value: str, *, field_name: str) -> datetime:
    raw = (value or "").strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must not be empty")
    candidate = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a valid ISO-8601 datetime",
        ) from exc


def _format_iso8601(value: datetime) -> str:
    iso = value.isoformat()
    if iso.endswith("+00:00"):
        return iso[:-6] + "Z"
    return iso
