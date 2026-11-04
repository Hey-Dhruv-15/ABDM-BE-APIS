"""Region and request-entry security enforcement middleware."""
from __future__ import annotations

from typing import Iterable

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.constants import HEADER_CORRELATION_ID, HEADER_REGION
from app.security.oauth2 import JWTValidator
from app.settings import settings


class RegionGuardMiddleware(BaseHTTPMiddleware):
    """Enforce region isolation and baseline request-entry headers."""

    def __init__(self, app, excluded_prefixes: Iterable[str] | None = None):
        super().__init__(app)
        self._excluded_prefixes = tuple(excluded_prefixes or ())

    async def dispatch(self, request: Request, call_next):
        if request.method.upper() == "OPTIONS" or not self._is_enforced_path(request.url.path):
            return await call_next(request)

        correlation_id = request.headers.get(HEADER_CORRELATION_ID) or ""

        if not self._is_source_ip_allowed(request):
            return self._error(
                status_code=status.HTTP_403_FORBIDDEN,
                code="IP_NOT_ALLOWED",
                message="Request IP is not allowed for this deployment",
                correlation_id=correlation_id,
            )

        region_header = request.headers.get(HEADER_REGION)
        resolved_region = (region_header or settings.REGION).strip().lower()
        configured_region = settings.REGION.strip().lower()

        if settings.ENFORCE_REGION_HEADER and not region_header:
            return self._error(
                status_code=status.HTTP_400_BAD_REQUEST,
                code="MISSING_REGION",
                message=f"{HEADER_REGION} header is required",
                correlation_id=correlation_id,
            )

        if resolved_region != configured_region:
            return self._error(
                status_code=status.HTTP_403_FORBIDDEN,
                code="CROSS_REGION_BLOCKED",
                message=f"Deployment region is '{configured_region}', but request region is '{resolved_region}'",
                correlation_id=correlation_id,
            )

        resolved_network = self._resolve_network(configured_region)
        if not resolved_network:
            return self._error(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                code="REGION_MISCONFIGURED",
                message=f"No enabled health network for region '{configured_region}'",
                correlation_id=correlation_id,
            )

        auth_header = request.headers.get("Authorization", "")
        if self._requires_bearer_auth(request):
            if settings.REQUIRE_AUTHORIZATION_HEADER and not auth_header.startswith("Bearer "):
                return self._error(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    code="AUTH_REQUIRED",
                    message="Authorization Bearer token is required",
                    correlation_id=correlation_id,
                )
            if settings.REQUIRE_JWT_VALIDATION and auth_header.startswith("Bearer "):
                token = auth_header[7:]
                try:
                    JWTValidator.decode(
                        token=token,
                        secret=settings.JWT_SECRET,
                        issuer=settings.JWT_EXPECTED_ISSUER,
                        audience=settings.JWT_EXPECTED_AUDIENCE,
                        public_key_pem=settings.JWT_PUBLIC_KEY_PEM,
                    )
                except Exception as exc:
                    return self._error(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        code="INVALID_TOKEN",
                        message=f"Bearer token validation failed: {exc}",
                        correlation_id=correlation_id,
                    )

        request.state.region = configured_region
        request.state.health_network = resolved_network
        response = await call_next(request)
        response.headers[HEADER_REGION] = configured_region
        return response

    @staticmethod
    def _requires_bearer_auth(request: Request) -> bool:
        """Return whether the request should enforce bearer-token auth."""
        path = request.url.path.rstrip("/")
        api_prefix = settings.API_V1_STR.rstrip("/")
        exempt_paths = {
            f"{api_prefix}/abdm/m1/sessions",
            f"{api_prefix}/hiecm/gateway/v3/sessions",
            f"{api_prefix}/abdm/m3/sessions",
            f"{api_prefix}/sessions",
            f"{api_prefix}{settings.ABDM_M2_SESSIONS_PATH.rstrip('/')}",
            f"{api_prefix}{settings.ABDM_M3_SESSIONS_PATH.rstrip('/')}",
            settings.ABDM_AUTH_PATH.rstrip("/"),
            f"{api_prefix}{settings.ABDM_AUTH_PATH.rstrip('/')}",
        }
        return path not in exempt_paths

    def _is_enforced_path(self, path: str) -> bool:
        enforced_prefix = settings.SECURITY_ENFORCED_PREFIX.strip()
        if not enforced_prefix:
            return True
        if not path.startswith(enforced_prefix):
            return False
        return not any(path.startswith(prefix) for prefix in self._excluded_prefixes)

    def _is_source_ip_allowed(self, request: Request) -> bool:
        allowed = [ip.strip() for ip in settings.ALLOWED_SOURCE_IPS.split(",") if ip.strip()]
        if not allowed:
            return True
        client_host = request.client.host if request.client else ""
        return client_host in allowed

    @staticmethod
    def _resolve_network(region: str) -> str:
        mapping = settings.region_network_map_dict()
        network = mapping.get(region.strip().lower(), "")
        if not network:
            return ""
        return network if settings.is_network_enabled(network) else ""

    @staticmethod
    def _error(status_code: int, code: str, message: str, correlation_id: str) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={
                "status": "error",
                "error": {"code": code, "message": message},
                "correlation_id": correlation_id or None,
            },
        )
