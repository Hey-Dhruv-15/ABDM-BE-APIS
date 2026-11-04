"""HTTP client wrapper for NABIDH calls."""
from typing import Any, Dict

import httpx

from app.logging.logger import get_logger
from app.nabidh.auth import NabidhAuthService
from app.settings import settings

logger = get_logger(__name__)


class NabidhClient:
    """Makes authenticated requests to NABIDH with token refresh on 401."""

    def __init__(self, auth_service: NabidhAuthService) -> None:
        self._auth_service = auth_service

    async def post(self, path: str, body: Dict[str, Any], extra_headers: Dict[str, str] | None = None) -> Any:
        """POST JSON to NABIDH."""
        return await self._request("POST", path, body, extra_headers=extra_headers)

    async def get(self, path: str, extra_headers: Dict[str, str] | None = None) -> Any:
        """GET from NABIDH."""
        return await self._request("GET", path, None, extra_headers=extra_headers)

    async def _request(
        self,
        method: str,
        path: str,
        json_body: Dict[str, Any] | None,
        extra_headers: Dict[str, str] | None = None,
    ) -> Any:
        url = f"{settings.NABIDH_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
        token = await self._auth_service.get_token()

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/fhir+json",
            "Accept": "application/fhir+json",
        }
        if extra_headers:
            headers.update(extra_headers)

        async with httpx.AsyncClient(timeout=settings.NABIDH_HTTP_TIMEOUT_SECONDS) as client:
            response = await client.request(method=method, url=url, headers=headers, json=json_body)
            if response.status_code == 401:
                logger.warning("NABIDH call returned 401, refreshing token and retrying once", endpoint=url)
                refreshed_token = await self._auth_service.get_token(force_refresh=True)
                headers["Authorization"] = f"Bearer {refreshed_token}"
                response = await client.request(method=method, url=url, headers=headers, json=json_body)

        response.raise_for_status()
        if response.content:
            try:
                return response.json()
            except ValueError:
                return {"status": "ok", "body": response.text}
        return {"status": "ok"}

