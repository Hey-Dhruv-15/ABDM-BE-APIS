"""HTTP client wrapper for ABDM gateway calls."""
import asyncio
import json
from typing import Any, Dict

import httpx

from fastapi import HTTPException
from app.abdm.auth import ABDMAuthService
from app.abdm.headers import (
    build_abdm_headers,
    buildABDMHeaders,
    generateRequestId,
    generateTimestamp,
    generateCorrelationId,
)
from app.logging.logger import get_logger
from app.settings import settings

logger = get_logger(__name__)

def _populate_missing_metadata(body: Any, path: str, request_id: str, timestamp: str) -> None:
    if isinstance(body, dict):
        if "on-discover" in path or "on-init" in path or "on-confirm" in path or "on-share" in path:
            return
        is_m3 = (
            "consent" in path
            or "health-information" in path
            or "m3" in path
            or "patients" in path
            or "patient" in path
        )
        if not is_m3:
            return

        if "request" in body and isinstance(body["request"], dict):
            target = body["request"]
        else:
            target = body

        if not target.get("requestId"):
            target["requestId"] = request_id
        if not target.get("timestamp"):
            target["timestamp"] = timestamp


def _handle_abdm_503(response: httpx.Response, url: str, headers: Dict[str, str], json_body: Dict[str, Any] | None) -> None:
    req_payload = json_body
    res_content = response.text
    req_id = headers.get("REQUEST-ID")
    corr_id = headers.get("X-Correlation-ID")

    logger.error(
        "ABDM 503 Service Unavailable",
        upstream_url=url,
        request_id=req_id,
        correlation_id=corr_id,
        request_payload=req_payload,
        response_content=res_content,
        response_headers=dict(response.headers),
    )

    raise HTTPException(
        status_code=503,
        detail={
            "message": "ABDM Gateway returned 503 Service Unavailable",
            "requestPayload": req_payload,
            "responseBody": res_content,
            "requestId": req_id,
            "correlationId": corr_id,
            "upstreamUrl": url,
            "diagnostics": {
                "status": "error",
                "error": {
                    "code": "UPSTREAM_503",
                    "message": "The ABDM Gateway is temporarily unavailable."
                }
            }
        }
    )


class ABDMGatewayClient:
    """Makes authenticated requests to ABDM with standard headers."""

    def __init__(self, auth_service: ABDMAuthService) -> None:
        self._auth_service = auth_service

    async def post(
        self,
        path: str,
        body: Dict[str, Any],
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> Any:
        """POST JSON to ABDM with automatic token refresh on 401."""
        return await self._request(
            method="POST",
            path=path,
            json_body=body,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )

    async def patch(
        self,
        path: str,
        body: Dict[str, Any] | None = None,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> Any:
        """PATCH JSON to ABDM with automatic token refresh on 401."""
        return await self._request(
            method="PATCH",
            path=path,
            json_body=body,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )

    async def put(
        self,
        path: str,
        body: Dict[str, Any] | None = None,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> Any:
        """PUT JSON to ABDM with automatic token refresh on 401."""
        return await self._request(
            method="PUT",
            path=path,
            json_body=body,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )

    async def get(
        self,
        path: str,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> Any:
        """GET from ABDM with automatic token refresh on 401."""
        return await self._request(
            method="GET",
            path=path,
            json_body=None,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )

    async def get_response(
        self,
        path: str,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> httpx.Response:
        """GET from ABDM and return the raw response for binary downloads."""
        return await self._request_response(
            method="GET",
            path=path,
            json_body=None,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )

    async def request(
        self,
        method: str,
        path: str,
        body: Dict[str, Any] | None = None,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: Dict[str, str] | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> Any:
        """Generic request helper for ABDM APIs where method varies by contract."""
        return await self._request(
            method=method,
            path=path,
            json_body=body,
            include_participant_header=include_participant_header,
            participant_id=participant_id,
            participant_type=participant_type,
            base_url=base_url,
            extra_headers=extra_headers,
            include_cm_header=include_cm_header,
            include_auth_header=include_auth_header,
        )

    async def _request(
        self,
        method: str,
        path: str,
        json_body: Dict[str, Any] | None,
        include_participant_header: bool,
        participant_id: str | None,
        participant_type: str | None,
        base_url: str | None,
        extra_headers: Dict[str, str] | None,
        include_cm_header: bool,
        include_auth_header: bool,
    ) -> Any:
        resolved_base = base_url or settings.ABDM_BASE_URL
        url = f"{resolved_base.rstrip('/')}/{path.lstrip('/')}"
        token = await self._auth_service.get_token() if include_auth_header else ""
        resolved_participant_type = participant_type or settings.ABDM_PARTICIPANT_TYPE
        resolved_participant_id = (
            participant_id
            if participant_id is not None
            else (settings.ABDM_PARTICIPANT_ID if include_participant_header else "")
        )

        request_id = generateRequestId()
        timestamp = generateTimestamp()
        correlation_id = generateCorrelationId()

        if json_body is not None:
            _populate_missing_metadata(json_body, path, request_id, timestamp)

        headers = buildABDMHeaders(
            access_token=token,
            cm_id=settings.ABDM_CM_ID or "sbx",
            region=settings.REGION or "india",
            integration=settings.ABDM_INTEGRATION_ID or "test-relay",
            correlation_id=correlation_id,
            request_id=request_id,
            timestamp=timestamp,
            participant_id=resolved_participant_id,
            participant_type=resolved_participant_type,
        )
        if extra_headers:
            headers.update(extra_headers)

        is_abha_v3 = ("abhasbx.abdm.gov.in" in resolved_base or "/abha/" in path) and not ("/hiecm/" in path or "/bridges/" in path)
        if is_abha_v3:
            headers.pop("X-CM-ID", None)
            headers.pop("X-Region", None)
            headers.pop("X-Integration", None)
            headers.pop("X-Correlation-ID", None)
            headers.pop("X-HIP-ID", None)
            headers.pop("X-HIU-ID", None)

        headers["REQUEST-ID"] = generateRequestId()
        if not (extra_headers and "TIMESTAMP" in extra_headers):
            headers["TIMESTAMP"] = timestamp
        if method.upper() == "GET":
            headers.pop("Content-Type", None)

        async with httpx.AsyncClient(timeout=settings.ABDM_HTTP_TIMEOUT_SECONDS) as client:
            logger.info("ABDM URL: %s", url)
            logger.info("Headers: %s", _mask_sensitive_headers(headers))
            logger.info("Payload: %s", json.dumps(json_body, indent=2))
            response = await _send_with_transient_retries(
                client=client,
                method=method,
                url=url,
                headers=headers,
                json_body=json_body,
            )
            if response.status_code == 503:
                _handle_abdm_503(response, url, headers, json_body)
            logger.info("ABDM Status: %s", response.status_code)
            logger.info("ABDM Response: %s", response.text)
            if include_auth_header and response.status_code == 401:
                logger.warning("ABDM call returned 401, refreshing token and retrying once", endpoint=url)
                refreshed_token = await self._auth_service.get_token(force_refresh=True)

                request_id = generateRequestId()
                timestamp = generateTimestamp()
                correlation_id = generateCorrelationId()
                if json_body is not None:
                    _populate_missing_metadata(json_body, path, request_id, timestamp)

                headers = buildABDMHeaders(
                    access_token=refreshed_token,
                    cm_id=settings.ABDM_CM_ID or "sbx",
                    region=settings.REGION or "india",
                    integration=settings.ABDM_INTEGRATION_ID or "test-relay",
                    correlation_id=correlation_id,
                    request_id=request_id,
                    timestamp=timestamp,
                    participant_id=resolved_participant_id,
                    participant_type=resolved_participant_type,
                )
                if extra_headers:
                    headers.update(extra_headers)

                if is_abha_v3:
                    headers.pop("X-CM-ID", None)
                    headers.pop("X-Region", None)
                    headers.pop("X-Integration", None)
                    headers.pop("X-Correlation-ID", None)
                    headers.pop("X-HIP-ID", None)
                    headers.pop("X-HIU-ID", None)

                headers["REQUEST-ID"] = generateRequestId()
                if not (extra_headers and "TIMESTAMP" in extra_headers):
                    headers["TIMESTAMP"] = timestamp
                if method.upper() == "GET":
                    headers.pop("Content-Type", None)

                logger.info(
                    "Retrying outbound ABDM request",
                    method=method,
                    url=url,
                    headers=_mask_sensitive_headers(headers),
                    body=json_body,
                )
                response = await _send_with_transient_retries(
                    client=client,
                    method=method,
                    url=url,
                    headers=headers,
                    json_body=json_body,
                )
                if response.status_code == 503:
                    _handle_abdm_503(response, url, headers, json_body)
                logger.info(
                    "Inbound ABDM response after retry",
                    method=method,
                    url=url,
                    status_code=response.status_code,
                    response=_response_log_body(response),
                )

        response.raise_for_status()
        if response.content:
            return response.json()
        if method.upper() == "GET":
            return None
        return {"status": "ok"}

    async def _request_response(
        self,
        method: str,
        path: str,
        json_body: Dict[str, Any] | None,
        include_participant_header: bool,
        participant_id: str | None,
        participant_type: str | None,
        base_url: str | None,
        extra_headers: Dict[str, str] | None,
        include_cm_header: bool,
        include_auth_header: bool,
    ) -> httpx.Response:
        resolved_base = base_url or settings.ABDM_BASE_URL
        url = f"{resolved_base.rstrip('/')}/{path.lstrip('/')}"
        token = await self._auth_service.get_token() if include_auth_header else ""
        resolved_participant_type = participant_type or settings.ABDM_PARTICIPANT_TYPE
        resolved_participant_id = (
            participant_id
            if participant_id is not None
            else (settings.ABDM_PARTICIPANT_ID if include_participant_header else "")
        )

        request_id = generateRequestId()
        timestamp = generateTimestamp()
        correlation_id = generateCorrelationId()

        if json_body is not None:
            _populate_missing_metadata(json_body, path, request_id, timestamp)

        headers = buildABDMHeaders(
            access_token=token,
            cm_id=settings.ABDM_CM_ID or "sbx",
            region=settings.REGION or "india",
            integration=settings.ABDM_INTEGRATION_ID or "test-relay",
            correlation_id=correlation_id,
            request_id=request_id,
            timestamp=timestamp,
            participant_id=resolved_participant_id,
            participant_type=resolved_participant_type,
        )
        if not include_auth_header:
            headers.pop("Authorization", None)
        if not include_cm_header:
            headers.pop("X-CM-ID", None)
        if extra_headers:
            headers.update(extra_headers)

        # Preserve extra_headers values for REQUEST-ID, TIMESTAMP, and X-Correlation-ID if provided
        if not (extra_headers and "REQUEST-ID" in extra_headers):
            headers["REQUEST-ID"] = request_id
        if not (extra_headers and "TIMESTAMP" in extra_headers):
            headers["TIMESTAMP"] = timestamp
        if not (extra_headers and "X-Correlation-ID" in extra_headers):
            headers["X-Correlation-ID"] = correlation_id

        async with httpx.AsyncClient(timeout=settings.ABDM_HTTP_TIMEOUT_SECONDS) as client:
            logger.info("ABDM URL: %s", url)
            logger.info("Headers: %s", _mask_sensitive_headers(headers))
            response = await _send_with_transient_retries(
                client=client,
                method=method,
                url=url,
                headers=headers,
                json_body=json_body,
            )
            if response.status_code == 503:
                _handle_abdm_503(response, url, headers, json_body)
            if include_auth_header and response.status_code == 401:
                logger.warning("ABDM call returned 401, refreshing token and retrying once", endpoint=url)
                refreshed_token = await self._auth_service.get_token(force_refresh=True)

                request_id = generateRequestId()
                timestamp = generateTimestamp()
                correlation_id = generateCorrelationId()
                if json_body is not None:
                    _populate_missing_metadata(json_body, path, request_id, timestamp)

                headers = buildABDMHeaders(
                    access_token=refreshed_token,
                    cm_id=settings.ABDM_CM_ID or "sbx",
                    region=settings.REGION or "india",
                    integration=settings.ABDM_INTEGRATION_ID or "test-relay",
                    correlation_id=correlation_id,
                    request_id=request_id,
                    timestamp=timestamp,
                    participant_id=resolved_participant_id,
                    participant_type=resolved_participant_type,
                )
                if not include_auth_header:
                    headers.pop("Authorization", None)
                if not include_cm_header:
                    headers.pop("X-CM-ID", None)
                if extra_headers:
                    headers.update(extra_headers)

                # Force overwrite retry dynamic headers
                headers["REQUEST-ID"] = request_id
                headers["TIMESTAMP"] = timestamp
                headers["X-Correlation-ID"] = correlation_id

                response = await _send_with_transient_retries(
                    client=client,
                    method=method,
                    url=url,
                    headers=headers,
                    json_body=json_body,
                )
                if response.status_code == 503:
                    _handle_abdm_503(response, url, headers, json_body)

        response.raise_for_status()
        return response


def _mask_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    masked = dict(headers)
    for key in ("Authorization", "X-LINK-TOKEN", "X-token", "X-Token"):
        if key in masked:
            masked[key] = "***masked***"
    return masked


def _response_log_body(response: httpx.Response) -> Any:
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return response.text


async def _send_with_transient_retries(
    *,
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: Dict[str, str],
    json_body: Dict[str, Any] | None,
) -> httpx.Response:
    """Retry transient gateway failures before surfacing the response."""
    attempts = max(int(settings.ABDM_HTTP_RETRY_ATTEMPTS), 1)
    last_error: httpx.HTTPError | None = None
    for attempt in range(1, attempts + 1):
        try:
            response = await client.request(method=method, url=url, headers=headers, json=json_body)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_error = exc
            if attempt >= attempts:
                raise
        else:
            if response.status_code not in {408, 429, 500, 502, 503, 504} or attempt >= attempts:
                return response
        await asyncio.sleep(min(0.2 * attempt, 1.0))

    if last_error:
        raise last_error
    raise httpx.TransportError("ABDM request retry loop exited without a response")
