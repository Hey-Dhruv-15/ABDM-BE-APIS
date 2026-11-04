"""Token generation and in-memory caching for ABDM session auth."""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

import httpx

from app.abdm.headers import utc_iso_timestamp
from app.abdm.schemas import SessionTokenResponse
from app.logging.logger import get_logger
from app.settings import settings

logger = get_logger(__name__)


class ABDMAuthError(Exception):
    """Raised when ABDM authentication fails."""


class ABDMAuthService:
    """Manages ABDM access token lifecycle with in-memory caching."""

    def __init__(self) -> None:
        self._access_token: Optional[str] = None
        self._token_type: str = "Bearer"
        self._expires_at: Optional[datetime] = None
        self._lock = asyncio.Lock()

    def _is_cached_token_valid(self) -> bool:
        if not self._access_token or not self._expires_at:
            return False
        skew = timedelta(seconds=max(settings.ABDM_TOKEN_REFRESH_SKEW_SECONDS, 0))
        return datetime.now(timezone.utc) + skew < self._expires_at

    async def get_token(self, force_refresh: bool = False) -> str:
        """Get a valid access token from cache or by refreshing from ABDM."""
        if not force_refresh and self._is_cached_token_valid():
            return self._access_token or ""

        async with self._lock:
            if not force_refresh and self._is_cached_token_valid():
                return self._access_token or ""

            await self._refresh_token()
            return self._access_token or ""

    def token_expiry(self) -> Optional[datetime]:
        """Expose token expiry time for diagnostics endpoints."""
        return self._expires_at

    async def _refresh_token(self) -> None:
        if not settings.ABDM_CLIENT_ID or not settings.ABDM_CLIENT_SECRET:
            raise ABDMAuthError("ABDM credentials are missing in environment configuration")

        if settings.ENFORCE_NETWORK_LOCK:
            expected_client_id = settings.ABDM_EXPECTED_CLIENT_ID.strip()
            if expected_client_id and settings.ABDM_CLIENT_ID.strip() != expected_client_id:
                raise ABDMAuthError(
                    "Deployment network lock failed: configured client ID does not match expected client ID"
                )

            expected_base_url = settings.ABDM_EXPECTED_BASE_URL.strip().rstrip("/")
            configured_base_url = settings.ABDM_BASE_URL.strip().rstrip("/")
            if expected_base_url and configured_base_url != expected_base_url:
                raise ABDMAuthError(
                    "Deployment network lock failed: configured ABDM base URL does not match expected base URL"
                )

        url = f"{settings.ABDM_BASE_URL.rstrip('/')}/{settings.ABDM_AUTH_PATH.lstrip('/')}"
        payload = {
            "clientId": settings.ABDM_CLIENT_ID,
            "clientSecret": settings.ABDM_CLIENT_SECRET,
            "grantType": settings.ABDM_GRANT_TYPE,
        }
        headers = {
            "REQUEST-ID": str(uuid4()),
            "TIMESTAMP": utc_iso_timestamp(),
            "X-CM-ID": settings.ABDM_CM_ID,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=settings.ABDM_HTTP_TIMEOUT_SECONDS) as client:
                logger.info(
                    "ABDM auth request",
                    endpoint=url,
                    headers=headers,
                    payload={
                        "clientId": "***configured***" if settings.ABDM_CLIENT_ID else "",
                        "clientSecret": "***configured***" if settings.ABDM_CLIENT_SECRET else "",
                        "grantType": settings.ABDM_GRANT_TYPE,
                    },
                )
                response = await client.post(url, headers=headers, json=payload)
            logger.info(
                "ABDM auth response",
                endpoint=url,
                status_code=response.status_code,
                response=_response_log_body(response),
            )
            response.raise_for_status()
            token_payload = SessionTokenResponse.model_validate(response.json())
        except httpx.HTTPStatusError as exc:
            response_body = _response_log_body(exc.response)
            logger.error(
                "ABDM auth failed with non-success status",
                status_code=exc.response.status_code,
                endpoint=url,
                response=response_body,
            )
            raise ABDMAuthError(
                f"ABDM auth request failed with status {exc.response.status_code}: {response_body}"
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("ABDM auth call failed", endpoint=url, error=str(exc))
            raise ABDMAuthError("ABDM auth call failed") from exc

        self._access_token = token_payload.access_token
        self._token_type = token_payload.token_type
        self._expires_at = datetime.now(timezone.utc) + timedelta(seconds=token_payload.expires_in)

        logger.info(
            "ABDM token refreshed successfully",
            expires_at=self._expires_at.isoformat() if self._expires_at else None,
        )


def _response_log_body(response: httpx.Response) -> object:
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return response.text
