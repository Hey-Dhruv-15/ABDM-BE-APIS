"""
API dependencies for the Gateway.
Provides dependency injection functions for request context and shared resources.
"""
from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.core.engine.context import RequestContext
from app.core.engine.pipeline import PipelineEngine
from app.config.loader import ConfigLoader
from app.abdm.auth import ABDMAuthService
from app.abdm.client import ABDMGatewayClient
from app.nabidh.auth import NabidhAuthService
from app.nabidh.client import NabidhClient
from app.settings import settings


# Global instances (will be set during app startup via lifecycle)
_config_loader: Optional[ConfigLoader] = None
_pipeline_engine: Optional[PipelineEngine] = None
_abdm_auth_service: Optional[ABDMAuthService] = None
_abdm_gateway_client: Optional[ABDMGatewayClient] = None
_nabidh_auth_service: Optional[NabidhAuthService] = None
_nabidh_client: Optional[NabidhClient] = None


def set_config_loader(loader: ConfigLoader) -> None:
    """Set the global config loader instance."""
    global _config_loader
    _config_loader = loader


def set_pipeline_engine(engine: PipelineEngine) -> None:
    """Set the global pipeline engine instance."""
    global _pipeline_engine
    _pipeline_engine = engine


def set_abdm_auth_service(service: ABDMAuthService) -> None:
    """Set the global ABDM auth service instance."""
    global _abdm_auth_service
    _abdm_auth_service = service


def set_abdm_gateway_client(client: ABDMGatewayClient) -> None:
    """Set the global ABDM gateway client instance."""
    global _abdm_gateway_client
    _abdm_gateway_client = client


def set_nabidh_auth_service(service: NabidhAuthService) -> None:
    """Set the global NABIDH auth service instance."""
    global _nabidh_auth_service
    _nabidh_auth_service = service


def set_nabidh_client(client: NabidhClient) -> None:
    """Set the global NABIDH client instance."""
    global _nabidh_client
    _nabidh_client = client


def get_config_loader() -> ConfigLoader:
    """Get the global config loader instance."""
    if _config_loader is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Config loader not initialized"
        )
    return _config_loader


def get_pipeline_engine() -> PipelineEngine:
    """Get the global pipeline engine instance."""
    if _pipeline_engine is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pipeline engine not initialized"
        )
    return _pipeline_engine


def get_abdm_auth_service() -> ABDMAuthService:
    """Get the global ABDM auth service instance."""
    if _abdm_auth_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ABDM auth service not initialized",
        )
    return _abdm_auth_service


def get_abdm_gateway_client() -> ABDMGatewayClient:
    """Get the global ABDM gateway client instance."""
    if _abdm_gateway_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ABDM gateway client not initialized",
        )
    return _abdm_gateway_client


def get_nabidh_auth_service() -> NabidhAuthService:
    """Get the global NABIDH auth service instance."""
    if _nabidh_auth_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NABIDH auth service not initialized",
        )
    return _nabidh_auth_service


def get_nabidh_client() -> NabidhClient:
    """Get the global NABIDH client instance."""
    if _nabidh_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NABIDH client not initialized",
        )
    return _nabidh_client


def get_nabidh_client_optional() -> Optional[NabidhClient]:
    """Get NABIDH client when available; return None if disabled/uninitialized."""
    return _nabidh_client


async def get_request_context(
    request: Request,
    x_integration: Annotated[
        Optional[str],
        Header(
            description=(
                "Optional integration profile id used to load routing/auth config from "
                "`app/config/integrations`. Pass values like `default`, `abha`, or `nabidh` "
                "(based on your configured integration names). If omitted, `default` is used."
            ),
            examples=["default", "abha", "nabidh"],
        ),
    ] = None,
) -> RequestContext:
    """
    Create a RequestContext from the incoming request.
    
    Extracts:
    - X-Integration header for the integration ID
    - Client IP from request
    - Integration config based on the header
    
    Args:
        request: The FastAPI request object
        x_integration: Optional X-Integration header value
        
    Returns:
        RequestContext populated with request details and integration config
        
    Raises:
        HTTPException: If integration is not found when required
    """
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Use header value or default
    integration_id = x_integration or "default"
    
    # Get integration config from loader
    loader = get_config_loader()
    integration_config = loader.get_integration(integration_id)
    
    if integration_config is None and x_integration:
        # Only raise error if integration was explicitly requested
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{x_integration}' not found"
        )
    
    # Create context with config
    context = RequestContext(
        integration_id=integration_id,
        client_ip=client_ip,
        integration_config=integration_config.model_dump() if integration_config else {},
        region=getattr(request.state, "region", None),
        health_network=getattr(request.state, "health_network", None),
    )
    
    # --- Security Check ---
    if integration_config:
        from app.security.auth_factory import AuthFactory
        auth_config = integration_config.auth
        
        handler = AuthFactory.get_handler(auth_config.type, auth_config.config)
        if handler:
            # Perform authentication
            await handler.authenticate(request)
            
    return context


# Type alias for dependency injection
RequestContextDep = Annotated[RequestContext, Depends(get_request_context)]

_docs_bearer = HTTPBearer(auto_error=False)


async def get_security_headers_for_docs(
    authorization: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(_docs_bearer),
    ] = None,
    x_region: Annotated[
        str,
        Header(
            alias="X-Region",
            description=(
                "Request region code (for example `india`, `uae`). "
                "Required when `ENFORCE_REGION_HEADER=true`."
            ),
            examples=["india", "uae"],
        ),
    ] = "india",
    x_integration: Annotated[
        str,
        Header(
            alias="X-Integration",
            description=(
                "Use this header: `X-Integration`. "
                "Set only the integration profile name from your YAML config "
                "(for example: `test-relay`, `default`, `abha`, `nabidh`)."
                " Do not include another header string here (for example, do not send "
                "`X-CM-ID: sbx` as the value)."
            ),
            examples=["test-relay", "default", "abha"],
        ),
    ] = "test-relay",
    x_cm_id: Annotated[
        str,
        Header(
            alias="X-CM-ID",
            description=(
                "Use this header: `X-CM-ID` (ABDM calls). "
                "Send as a separate header from `X-Integration`. "
                "Sandbox value is typically `sbx`."
            ),
            examples=["sbx"],
        ),
    ] = "sbx",
    x_correlation_id: Annotated[
        Optional[str],
        Header(
            alias="X-Correlation-ID",
            description=(
                "Use this header: `X-Correlation-ID` (optional). "
                "Send your own request trace ID to track a flow end-to-end."
            ),
            examples=["req-1234567890"],
        ),
    ] = None,
    request_id: Annotated[
        Optional[str],
        Header(
            alias="REQUEST-ID",
            description="ABDM request UUID. Required by ABDM callback and gateway certification APIs.",
            examples=["4f54b0f8-1b7d-4a99-a2ef-9f810f55e2e7"],
        ),
    ] = None,
    timestamp: Annotated[
        Optional[str],
        Header(
            alias="TIMESTAMP",
            description="ABDM request timestamp in ISO-8601 UTC format.",
            examples=["2022-10-06T10:10:00.587Z"],
        ),
    ] = None,
) -> None:
    """Documentation-only dependency to expose security headers in Swagger."""
    _ = (authorization, x_region, x_integration, x_cm_id, x_correlation_id, request_id, timestamp)
