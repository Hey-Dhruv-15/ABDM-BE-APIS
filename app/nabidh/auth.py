"""OAuth token generation and in-memory caching for NABIDH."""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.logging.logger import get_logger
from app.nabidh.schemas import NabidhTokenResponse
from app.settings import settings

logger = get_logger(__name__)


class NabidhAuthError(Exception):
    """Raised when NABIDH authentication fails."""


class NabidhAuthService:
    """Manages NABIDH OAuth token lifecycle with in-memory caching."""

    def __init__(self) -> None:
        self._access_token: Optional[str] = None
        self._token_type: str = "Bearer"
        self._expires_at: Optional[datetime] = None
        self._lock = asyncio.Lock()

    def _is_cached_token_valid(self) -> bool:
        if not self._access_token or not self._expires_at:
            return False
        skew = timedelta(seconds=max(settings.NABIDH_TOKEN_REFRESH_SKEW_SECONDS, 0))
        return datetime.now(timezone.utc) + skew < self._expires_at

    async def get_token(self, force_refresh: bool = False) -> str:
        """Get a valid access token from cache or by refreshing from NABIDH."""
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
        if not settings.NABIDH_CLIENT_ID or not settings.NABIDH_CLIENT_SECRET:
            raise NabidhAuthError("NABIDH credentials are missing in environment configuration")

        url = f"{settings.NABIDH_BASE_URL.rstrip('/')}/{settings.NABIDH_AUTH_PATH.lstrip('/')}"
        payload = {
            "grant_type": settings.NABIDH_GRANT_TYPE,
            "client_id": settings.NABIDH_CLIENT_ID,
            "client_secret": settings.NABIDH_CLIENT_SECRET,
        }
        if settings.NABIDH_SCOPE:
            payload["scope"] = settings.NABIDH_SCOPE

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            async with httpx.AsyncClient(timeout=settings.NABIDH_HTTP_TIMEOUT_SECONDS) as client:
                response = await client.post(url, data=payload, headers=headers)
            response.raise_for_status()
            token_payload = NabidhTokenResponse.model_validate(response.json())
        except httpx.HTTPStatusError as exc:
            logger.error(
                "NABIDH auth failed with non-success status",
                status_code=exc.response.status_code,
                endpoint=url,
            )
            raise NabidhAuthError("NABIDH auth request failed") from exc
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("NABIDH auth call failed", endpoint=url, error=str(exc))
            raise NabidhAuthError("NABIDH auth call failed") from exc

        self._access_token = token_payload.access_token
        self._token_type = token_payload.token_type
        self._expires_at = datetime.now(timezone.utc) + timedelta(seconds=token_payload.expires_in)

        logger.info(
            "NABIDH token refreshed successfully",
            expires_at=self._expires_at.isoformat() if self._expires_at else None,
        )

