"""Header validation middleware for ABDM callback compliance."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable
from uuid import UUID, uuid4

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from app.settings import settings


def _utc_iso_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ABDMHeaderValidationMiddleware(BaseHTTPMiddleware):
    """Validate required ABDM headers on callback endpoints."""

    def __init__(
        self,
        app,
        *,
        require_paths: Iterable[str] | None = None,
        health_request_path: str | None = None,
    ) -> None:
        super().__init__(app)
        self._require_paths = set(require_paths or [])
        self._health_request_path = health_request_path

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method.upper() != "POST":
            return await call_next(request)

        path = request.url.path
        if self._require_paths and path not in self._require_paths:
            return await call_next(request)

        body = await request.body()
        request._body = body
        payload = {}
        if body:
            try:
                body_str = body.decode("utf-8", errors="replace")
                payload = json.loads(body_str, strict=False)
            except Exception:
                try:
                    payload = json.loads(body)
                except Exception:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={"detail": "Invalid JSON body"},
                    )

        if (
            self._health_request_path
            and path == self._health_request_path
            and isinstance(payload, dict)
            and "request" in payload
        ):
            return await call_next(request)

        try:
            _validate_abdm_headers(request=request, payload=payload)
        except HTTPException as exc:
            if isinstance(exc.detail, dict) and {"code", "message"} <= set(exc.detail):
                return JSONResponse(status_code=exc.status_code, content=exc.detail)
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        return await call_next(request)


def _validate_abdm_headers(*, request: Request, payload: dict) -> None:
    headers = request.headers
    cm_id = headers.get("X-CM-ID")
    payload_request_id = payload.get("requestId") if isinstance(payload, dict) else None
    request_id = headers.get("REQUEST-ID") or (payload_request_id if isinstance(payload_request_id, str) and payload_request_id else None) or str(uuid4())
    timestamp = headers.get("TIMESTAMP") or _utc_iso_timestamp()
    request.state.abdm_request_id = request_id
    request.state.abdm_timestamp = timestamp

    path = request.url.path
    normalized_path = path
    if settings.API_V1_STR and path.startswith(settings.API_V1_STR):
        normalized_path = path[len(settings.API_V1_STR):]

    outbound_paths = {
        "/consent-requests/init",
        "/consents/fetch",
        "/health-information/request",
        "/health-information/cm/notify",
        "/m3/links/link/token/init",
        "/m3/links/link/token/confirm",
        "/m3/links/context/notify",
        "/hiecm/consent/v3/request/init",
        "/hiecm/consent/v3/fetch",
        "/hiecm/data-flow/v3/health-information/request",
        "/hiecm/data-flow/v3/health-information/notify",
    }
    is_outbound = normalized_path in outbound_paths

    if settings.ABDM_CALLBACK_AUTH_MODE == "none" and is_outbound:
        return

    missing = [name for name, value in (("X-CM-ID", cm_id),) if not value]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing ABDM headers: {', '.join(missing)}",
        )

    if settings.ABDM_CALLBACK_AUTH_MODE == "none":
        return

    try:
        UUID(request_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "ABDM-1030", "message": "Invalid request ID"},
        ) from exc

    expected_cm_id = settings.ABDM_CM_ID.strip()
    if expected_cm_id and cm_id != expected_cm_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-CM-ID header",
        )

    timestamp_dt = _parse_abdm_timestamp(timestamp)
    tolerance = max(int(settings.ABDM_HEADER_TIMESTAMP_TOLERANCE_SECONDS), 1)
    delta = abs((datetime.now(timezone.utc) - timestamp_dt).total_seconds())
    if delta > tolerance:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "ABDM-1016", "message": "Invalid Time stamp"},
        )

    if isinstance(payload, dict):
        payload_request_id = payload.get("requestId")
        if payload_request_id and payload_request_id != request_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="REQUEST-ID header does not match body requestId",
            )


def _parse_abdm_timestamp(value: str) -> datetime:
    raw = (value or "").strip()
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "ABDM-1016", "message": "Invalid Time stamp"},
        )
    candidate = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "ABDM-1016", "message": "Invalid Time stamp"},
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
