"""
FastAPI application entry point.
Initializes the app, configures middleware, and registers routes.
"""
from fastapi import FastAPI, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
import time

from app.settings import settings
from app.lifecycle import lifespan
from app.api.router import api_router
from app.api.routes import abdm as abdm_routes
from app.logging.logger import get_logger
from app.logging.request_context import CorrelationIdMiddleware
from app.security.abdm_header_guard import ABDMHeaderValidationMiddleware
from app.security.region_guard import RegionGuardMiddleware

logger = get_logger(__name__)


HIDDEN_API_PATHS = {
    f"{settings.API_V1_STR}/inbound/process",
    f"{settings.API_V1_STR}/inbound/validate",
    f"{settings.API_V1_STR}/outbound/send",
    f"{settings.API_V1_STR}/outbound",
    f"{settings.API_V1_STR}/outbound/",
    f"{settings.API_V1_STR}/admin/config/reload",
    f"{settings.API_V1_STR}/admin/config",
    f"{settings.API_V1_STR}/test/receiver",
}


def _remove_hidden_api_routes(app: FastAPI) -> None:
    """Remove non-ABDM utility routes from the exposed API surface."""
    app.router.routes = [
        route
        for route in app.router.routes
        if getattr(route, "path", "") not in HIDDEN_API_PATHS
    ]


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    @app.get("/health", tags=["Health"])
    async def health_check():
        return {"status": "healthy"}        
    # --- Middleware ---
    
    # 1. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_origin_regex=r"https?://.*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
    
    # 2. Correlation ID Tracking
    app.add_middleware(CorrelationIdMiddleware)

    # 3. Region and entry security guard
    app.add_middleware(
        RegionGuardMiddleware,
        excluded_prefixes=(
            "/",
            "/favicon.ico",
            "/docs",
            "/redoc",
            f"{settings.API_V1_STR}/care-contexts/notify",
            f"{settings.API_V1_STR}/consent/request/init",
            f"{settings.API_V1_STR}/consent/request/on-init",
            f"{settings.API_V1_STR}/consents/fetch",
            f"{settings.API_V1_STR}/consents/on-fetch",
            f"{settings.API_V1_STR}/health-information/cm/notify",
            f"{settings.API_V1_STR}/health-information/on-request",
            f"{settings.API_V1_STR}/health-information/request",
            f"{settings.API_V1_STR}/health-information/notify",
            f"{settings.API_V1_STR}/links/link/token/init",
            f"{settings.API_V1_STR}/links/link/token/confirm",
            f"{settings.API_V1_STR}/links/context/notify",
            f"{settings.API_V1_STR}/m3/scan-share/qr",
            f"{settings.API_V1_STR}/m3/scan-share/daily-tokens",
            f"{settings.API_V1_STR}/patients/profile/share",
            f"{settings.API_V1_STR}/v3/hip/patient/share",
            f"{settings.API_V1_STR}/v3/hiu/patient/on-share",
            "/api/v3/hip/patient/share",
            "/api/v3/hiu/patient/on-share",
            f"{settings.API_V1_STR}/openapi.json",
            f"{settings.API_V1_STR}/consent/notification",
            f"{settings.API_V1_STR}/health-information/transfer",
            f"{settings.API_V1_STR}/health-information/ack",
            f"{settings.API_V1_STR}/health-information/data",
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links",
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/context/notify",
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/sms/notify2",
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/sms/on-notify",
            f"{settings.API_V1_STR}/care-contexts/discover",
            f"{settings.API_V1_STR}/links/link/init",
            f"{settings.API_V1_STR}/links/link/confirm",
            f"{settings.API_V1_STR}/profile/share",
            f"{settings.API_V1_STR}/v3/hip/token/on-generate-token",
            f"{settings.API_V1_STR}/api/v3/hip/token/on-generate-token",
            "/v3/hip/token/on-generate-token",
            "/api/v3/hip/token/on-generate-token",
            "/v3/token/on-generate-token",
            "/api/v3/token/on-generate-token",
            "/hiecm/hip/v3/token/on-generate-token",
            "/api/hiecm/hip/v3/token/on-generate-token",
            f"{settings.API_V1_STR}/v3/hip/link/on-care-context",
            f"{settings.API_V1_STR}/api/v3/hip/link/on-care-context",
            "/v3/hip/link/on-care-context",
            "/api/v3/hip/link/on-care-context",
            f"{settings.API_V1_STR}/v3/link/on_carecontext",
            f"{settings.API_V1_STR}/api/v3/link/on_carecontext",
            "/v3/link/on_carecontext",
            "/api/v3/link/on_carecontext",
            f"{settings.API_V1_STR}/v3/hip/patient/care-context/discover",
            f"{settings.API_V1_STR}/v3/hip/link/care-context/init",
            f"{settings.API_V1_STR}/v3/hip/link/care-context/confirm",
            f"{settings.API_V1_STR}/v3/consent/request/hip/notify",
            f"{settings.API_V1_STR}/v3/hip/health-information/request",
            f"{settings.API_V1_STR}/v3/links/context/on-notify",
            f"{settings.API_V1_STR}/v3/profile/account",
            "/v3/hip/patient/care-context/discover",
            "/api/v3/hip/patient/care-context/discover",
            "/v3/hip/link/care-context/init",
            "/api/v3/hip/link/care-context/init",
            "/v3/hip/link/care-context/confirm",
            "/api/v3/hip/link/care-context/confirm",
            "/v3/consent/request/hip/notify",
            "/api/v3/consent/request/hip/notify",
            "/v3/hip/health-information/request",
            "/api/v3/hip/health-information/request",
            f"{settings.API_V1_STR}/admin/transactions",
            f"{settings.API_V1_STR}/admin/api-logs",
            f"{settings.API_V1_STR}/health-records",
        ),
    )

    # 4. ABDM Header Validation for callbacks
    abdm_callback_paths = (
        f"{settings.API_V1_STR}/m3/scan-share/qr",
        f"{settings.API_V1_STR}/consent-requests/init",
        f"{settings.API_V1_STR}/consent-requests/on-init",
        f"{settings.API_V1_STR}/consent-requests/notify",
        f"{settings.API_V1_STR}/consents/fetch",
        f"{settings.API_V1_STR}/consents/on-fetch",
        f"{settings.API_V1_STR}/health-information/request",
        f"{settings.API_V1_STR}/health-information/on-request",
        f"{settings.API_V1_STR}/health-information/notify",
        f"{settings.API_V1_STR}/health-information/cm/notify",
        f"{settings.API_V1_STR}/m3/links/link/token/init",
        f"{settings.API_V1_STR}/m3/links/link/token/confirm",
        f"{settings.API_V1_STR}/m3/links/context/notify",
        f"{settings.API_V1_STR}/patients/profile/share",
        f"{settings.API_V1_STR}/v3/hip/patient/share",
        f"{settings.API_V1_STR}/v3/hiu/patient/on-share",
        f"{settings.API_V1_STR}/consent/notification",
        f"{settings.API_V1_STR}/consent/acknowledge",
        f"{settings.API_V1_STR}/health-information/transfer",
        f"{settings.API_V1_STR}/health-information/ack",
        f"{settings.API_V1_STR}/health-information/data",
        f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links",
        f"{settings.API_V1_STR}/hiecm/hip/v3/link/context/notify",
        f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/sms/notify2",
        f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/sms/on-notify",
        f"{settings.API_V1_STR}/care-contexts/discover",
        f"{settings.API_V1_STR}/links/link/init",
        f"{settings.API_V1_STR}/links/link/confirm",
        f"{settings.API_V1_STR}/profile/share",
        f"{settings.API_V1_STR}/v3/hip/token/on-generate-token",
        f"{settings.API_V1_STR}/v3/hip/link/on-care-context",
        f"{settings.API_V1_STR}/v3/link/on_carecontext",
        f"{settings.API_V1_STR}/v3/hip/patient/care-context/discover",
        f"{settings.API_V1_STR}/v3/hip/link/care-context/init",
        f"{settings.API_V1_STR}/v3/hip/link/care-context/confirm",
        f"{settings.API_V1_STR}/v3/consent/request/hip/notify",
        f"{settings.API_V1_STR}/v3/hip/health-information/request",
        f"{settings.API_V1_STR}/v3/links/context/on-notify",
    )
    app.add_middleware(
        ABDMHeaderValidationMiddleware,
        require_paths=abdm_callback_paths,
        health_request_path=f"{settings.API_V1_STR}/health-information/request",
    )

    # 5. Request Logging Middleware
    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):
        """Middleware to log request details and processing time."""
        start_time = time.time()
        
        # Log request ingress
        logger.info("Request started", method=request.method, url=str(request.url))
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        
        logger.info(
            "Request completed",
            method=request.method,
            url=str(request.url),
            status_code=response.status_code,
            process_time_ms=round(process_time * 1000, 2),
            client_ip=request.client.host if request.client else None,
            region=getattr(request.state, "region", None),
            health_network=getattr(request.state, "health_network", None),
        )
        return response

    # --- Routers ---
    app.include_router(api_router, prefix=settings.API_V1_STR)
    _remove_hidden_api_routes(app)

    # Dedicated M2 Gateway Callback Router for root-level ABDM webhooks (Hidden from Swagger UI)
    from fastapi import APIRouter, Depends, Header
    m2_root_cb_router = APIRouter(include_in_schema=False)

    @m2_root_cb_router.post("/v3/hip/token/on-generate-token")
    @m2_root_cb_router.post("/api/v3/hip/token/on-generate-token")
    @m2_root_cb_router.post("/v3/token/on-generate-token")
    @m2_root_cb_router.post("/api/v3/token/on-generate-token")
    @m2_root_cb_router.post("/hiecm/hip/v3/token/on-generate-token")
    @m2_root_cb_router.post("/api/hiecm/hip/v3/token/on-generate-token")
    async def _m2_root_link_token_callback(request: Request):
        try:
            body_data = await request.json()
        except Exception:
            body_data = {}
        payload_obj = abdm_routes.M2LinkTokenCallbackPayload.model_validate(body_data)
        return await abdm_routes.m2_link_token_callback(request, payload_obj)

    @m2_root_cb_router.post("/v3/hip/link/on-care-context")
    @m2_root_cb_router.post("/api/v3/hip/link/on-care-context")
    @m2_root_cb_router.post("/v3/link/on_carecontext")
    @m2_root_cb_router.post("/api/v3/link/on_carecontext")
    async def _m2_root_link_care_context_callback(request: Request):
        body_data = await request.json()
        payload_obj = abdm_routes.M2LinkCareContextOnCareContextPayload.model_validate(body_data)
        auth_header = request.headers.get("Authorization", "")
        return await abdm_routes.m2_link_care_context_callback(request, payload_obj, authorization_header=auth_header)

    @m2_root_cb_router.post("/v3/hip/patient/care-context/discover")
    @m2_root_cb_router.post("/api/v3/hip/patient/care-context/discover")
    async def _m2_root_discovery_callback(request: Request):
        body_data = await request.json()
        return await abdm_routes.m2_user_initiated_discovery_callback(request, body_data)

    @m2_root_cb_router.post("/v3/hip/link/care-context/init")
    @m2_root_cb_router.post("/api/v3/hip/link/care-context/init")
    async def _m2_root_link_init_callback(request: Request):
        body_data = await request.json()
        return await abdm_routes.links_link_init(request, body_data)

    @m2_root_cb_router.post("/v3/hip/link/care-context/confirm")
    @m2_root_cb_router.post("/api/v3/hip/link/care-context/confirm")
    async def _m2_root_link_confirm_callback(request: Request):
        body_data = await request.json()
        return await abdm_routes.links_link_confirm(request, body_data)

    @m2_root_cb_router.post("/v3/hiu/consent/request/on-init")
    @m2_root_cb_router.post("/api/v3/hiu/consent/request/on-init")
    async def _m2_root_consent_on_init_callback(request: Request):
        body_data = await request.json()
        payload_obj = abdm_routes.HiuConsentRequestCallbackPayload.model_validate(body_data)
        return await abdm_routes.hiu_consent_request_on_init(request, payload_obj)

    @m2_root_cb_router.post("/v3/hiu/consent/on-fetch")
    @m2_root_cb_router.post("/api/v3/hiu/consent/on-fetch")
    async def _m2_root_consent_on_fetch_callback(request: Request):
        body_data = await request.json()
        payload_obj = abdm_routes.HiuConsentArtefactCallbackPayload.model_validate(body_data)
        return await abdm_routes.hiu_consent_on_fetch(request, payload_obj)

    @m2_root_cb_router.post("/v3/hiu/consent/request/on-status")
    @m2_root_cb_router.post("/api/v3/hiu/consent/request/on-status")
    @m2_root_cb_router.post("/consent-requests/on-status")
    async def _m2_root_consent_on_status_callback(request: Request):
        body_data = await request.json()
        return await abdm_routes.hiu_consent_request_on_status(request, body_data)

    @m2_root_cb_router.post("/v3/consent/request/hip/notify")
    @m2_root_cb_router.post("/api/v3/consent/request/hip/notify")
    @m2_root_cb_router.post("/v3/hiu/consent/request/notify")
    @m2_root_cb_router.post("/api/v3/hiu/consent/request/notify")
    @m2_root_cb_router.post("/consents/hiu/notify")
    @m2_root_cb_router.post("/api/v1/consents/hiu/notify")
    async def _m2_root_consent_notify_callback(request: Request):
        return await abdm_routes.hiu_consent_request_notify(request)

    @m2_root_cb_router.post("/v3/hip/health-information/request")
    @m2_root_cb_router.post("/api/v3/hip/health-information/request")
    async def _m2_root_health_info_request_callback(request: Request, response: Response):
        body_data = await request.json()
        payload_obj = abdm_routes.HiuHealthInformationRequestPayload.model_validate(body_data)
        return await abdm_routes.health_information_request(request, response, payload_obj)

    @m2_root_cb_router.post("/v3/hip/patient/share")
    @m2_root_cb_router.post("/api/v3/hip/patient/share")
    @m2_root_cb_router.post("/profile/share")
    @m2_root_cb_router.post("/api/profile/share")
    @m2_root_cb_router.post("/hiecm/patient-share/v3/share")
    @m2_root_cb_router.post("/api/hiecm/patient-share/v3/share")
    async def _m2_root_profile_share_callback(
        request: Request,
        request_id_header: str | None = Header(default=None, alias="REQUEST-ID"),
        timestamp_header: str | None = Header(default=None, alias="TIMESTAMP"),
        x_hip_id_header: str | None = Header(default=None, alias="X-HIP-ID"),
        client: abdm_routes.ABDMGatewayClient = Depends(abdm_routes.get_abdm_gateway_client),
    ):
        body_data = await request.json()
        payload_obj = abdm_routes.M3PatientSharePayload.model_validate(body_data)
        return await abdm_routes.m3_receive_patient_share(
            request=request,
            body=payload_obj,
            request_id_header=request_id_header,
            timestamp_header=timestamp_header,
            x_hip_id_header=x_hip_id_header,
            client=client,
        )

    app.include_router(m2_root_cb_router)

    @app.get("/", tags=["Health"])
    async def root():
        """Service Health & Discovery Root."""
        return {
            "name": "ABDM Gateway Service",
            "status": "online",
            "documentation": "/docs",
            "version": "1.0.0"
        }

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        """Return empty 204 for favicon requests."""
        return Response(status_code=204)

    # --- OpenAPI Filtering and Reordering ---
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            routes=app.routes,
        )
        paths = schema.get("paths", {})

        ALIAS_M1_PATHS = {
            f"{settings.API_V1_STR}/v3/profile/public/certificate",
            f"{settings.API_V1_STR}/v3/enrollment/request/otp",
            f"{settings.API_V1_STR}/v3/enrollment/enrol/byAadhaar",
            f"{settings.API_V1_STR}/v3/enrollment/request/mobile-otp",
            f"{settings.API_V1_STR}/v3/enrollment/auth/byAbdm",
            f"{settings.API_V1_STR}/v3/enrollment/abha-address/suggestions",
            f"{settings.API_V1_STR}/abha/v3/enrollment/abha-address/suggestions",
            f"{settings.API_V1_STR}/v3/enrollment/create/phrAddress",
            f"{settings.API_V1_STR}/abha/v3/enrollment/create/phrAddress",
            f"{settings.API_V1_STR}/v3/profile/account/abha-card",
            f"{settings.API_V1_STR}/v3/profile/account/abha/search",
            f"{settings.API_V1_STR}/v3/profile/login/request/otp",
            f"{settings.API_V1_STR}/v3/profile/login/verify",
            f"{settings.API_V1_STR}/v3/profile/account",
            f"{settings.API_V1_STR}/v3/profile/account/qrCode",
            f"{settings.API_V1_STR}/registration/aadhaar/generateOtp",
            f"{settings.API_V1_STR}/registration/aadhaar/verifyOTP",
            f"{settings.API_V1_STR}/registration/aadhaar/generateMobileOTP",
            f"{settings.API_V1_STR}/registration/aadhaar/verifyMobileOTP",
            f"{settings.API_V1_STR}/registration/aadhaar/createHealthIdWithPreVerified",
            f"{settings.API_V1_STR}/account/change/mobile/new/verifyOTP",
            f"{settings.API_V1_STR}/account/change/mobile/old/generateOTP",
            f"{settings.API_V1_STR}/account/change/mobile/aadhaar/generateOTP",
        }

        ordered_api_specs = [
            # ABDM M1 - Core Sessions & Public Certificate
            (f"{settings.API_V1_STR}/abdm/m1/sessions", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/profile/public/certificate", "ABDM M1"),

            # ABDM M1 - ABHA Creation (Enrollment)
            (f"{settings.API_V1_STR}/abha/v3/enrollment/request/otp/auto", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/enrollment/request/otp", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/enrollment/enrol/byAadhaar", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/enrollment/request/mobile-otp", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/enrollment/auth/byAbdm", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/address/suggestions/{{txnId}}", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/address/create", "ABDM M1"),

            # ABDM M1 - ABHA Card Download
            (f"{settings.API_V1_STR}/abha/v3/card/{{txnId}}", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/profile/account/abha-card", "ABDM M1"),

            # ABDM M1 - ABHA Search & Login
            (f"{settings.API_V1_STR}/abha/v3/profile/account/abha/search", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/profile/login/request/otp", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/profile/login/verify", "ABDM M1"),

            # ABDM M1 - Profile & Account Details
            (f"{settings.API_V1_STR}/abha/v3/profile/account", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/profile/account/qrCode", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/profile/account/request/otp", "ABDM M1"),
            (f"{settings.API_V1_STR}/abha/v3/profile/account/verify", "ABDM M1"),

            # ABDM M1 - Change Mobile Number
            (f"{settings.API_V1_STR}/account/change/mobile/new/generateOTP", "ABDM M1"),
            (f"{settings.API_V1_STR}/account/change/mobile/update/authentication", "ABDM M1"),

            # ABDM M2 - 1. Gateway & Setup
            (f"{settings.API_V1_STR}/hiecm/gateway/v3/sessions", "ABDM M2 - 1. Gateway & Setup"),
            (f"{settings.API_V1_STR}/api/hiecm/gateway/v3/sessions", "ABDM M2 - 1. Gateway & Setup"),
            (f"{settings.API_V1_STR}/hiecm/gateway/v3/bridge/url", "ABDM M2 - 1. Gateway & Setup"),
            (f"{settings.API_V1_STR}/api/hiecm/gateway/v3/bridge/url", "ABDM M2 - 1. Gateway & Setup"),
            (f"{settings.API_V1_STR}/v1/bridges/MutipleHRPAddUpdateServices", "ABDM M2 - 1. Gateway & Setup"),
            (f"{settings.API_V1_STR}/hiecm/gateway/v3/bridge-service/serviceId/{{serviceId}}", "ABDM M2 - 1. Gateway & Setup"),
            (f"{settings.API_V1_STR}/hiecm/gateway/v3/bridge-services", "ABDM M2 - 1. Gateway & Setup"),

            # ABDM M2 - 2. HIP-Initiated Linking
            (f"{settings.API_V1_STR}/hiecm/v3/token/generate-token", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/api/hiecm/v3/token/generate-token", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/hip/token/on-generate-token", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/api/v3/hip/token/on-generate-token", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/api/hiecm/hip/v3/link/carecontext", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/hip/link/on-care-context", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/link/on_carecontext", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/api/v3/link/on_carecontext", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/hip/v3/link/context/notify", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/links/context/on-notify", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/sms/notify2", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/sms/on-notify", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/hip/ondeactivate", "ABDM M2 - 2. HIP-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/hiu/ondeactivate", "ABDM M2 - 2. HIP-Initiated Linking"),

            # ABDM M2 - 3. User-Initiated Linking
            (f"{settings.API_V1_STR}/v3/hip/patient/care-context/discover", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/api/v3/hip/patient/care-context/discover", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/patient/care-context/on-discover", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/api/hiecm/user-initiated-linking/v3/patient/care-context/on-discover", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/patient/care-context/latest-discovery", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/link/care-context/init", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/hip/link/care-context/init", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/link/care-context/on-init", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/link/care-context/confirm", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/hip/link/care-context/confirm", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/link/care-context/on-confirm", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/hiu/patient/care-context/on-discover", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/hiu/patient/care-context/on-init", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/v3/hiu/patient/care-context/on-confirm", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/care-contexts/discover", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/links/link/init", "ABDM M2 - 3. User-Initiated Linking"),
            (f"{settings.API_V1_STR}/links/link/confirm", "ABDM M2 - 3. User-Initiated Linking"),

            # ABDM M2 - 4. Health Data Transfer & Consent
            (f"{settings.API_V1_STR}/v3/consent/request/hip/notify", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/api/v3/consent/request/hip/notify", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/hiecm/consent/v3/request/hip/on-notify", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/api/hiecm/consent/v3/request/hip/on-notify", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/v3/hip/health-information/request", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/api/v3/hip/health-information/request", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/hiecm/data-flow/v3/health-information/hip/on-request", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/api/hiecm/data-flow/v3/health-information/hip/on-request", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/hiecm/data-flow/v3/health-information/notify", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/api/hiecm/data-flow/v3/health-information/notify", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/health-information/data", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/health-information/transfer", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/health-information/notify", "ABDM M2 - 4. Health Data Transfer & Consent"),
            (f"{settings.API_V1_STR}/health-information/cm/notify", "ABDM M2 - 4. Health Data Transfer & Consent"),

            # ABDM M2 - 5. Scan & Share
            (f"{settings.API_V1_STR}/v3/hip/patient/share", "ABDM M2 - 5. Scan & Share"),
            (f"{settings.API_V1_STR}/api/v3/hip/patient/share", "ABDM M2 - 5. Scan & Share"),
            (f"{settings.API_V1_STR}/hiecm/patient-share/v3/on-share", "ABDM M2 - 5. Scan & Share"),
            (f"{settings.API_V1_STR}/api/hiecm/patient-share/v3/on-share", "ABDM M2 - 5. Scan & Share"),
            (f"{settings.API_V1_STR}/profile/share", "ABDM M2 - 5. Scan & Share"),
            (f"{settings.API_V1_STR}/m3/scan-share/qr", "ABDM M2 - 5. Scan & Share"),
            (f"{settings.API_V1_STR}/m3/scan-share/daily-tokens", "ABDM M2 - 5. Scan & Share"),
            (f"{settings.API_V1_STR}/m3/patients/profile/share", "ABDM M2 - 5. Scan & Share"),
            (f"{settings.API_V1_STR}/v3/hiu/patient/on-share", "ABDM M2 - 5. Scan & Share"),

            # ABDM M3 - Consent Management
            (f"{settings.API_V1_STR}/abdm/m3/sessions", "ABDM M3 - Consent Management"),
            (f"{settings.API_V1_STR}/sessions", "ABDM M3 - Consent Management"),
            (f"{settings.API_V1_STR}/consent-requests/init", "ABDM M3 - Consent Management"),
            (f"{settings.API_V1_STR}/consent-requests/on-init", "ABDM M3 - Consent Management"),
            (f"{settings.API_V1_STR}/consent/notification", "ABDM M3 - Consent Management"),
            (f"{settings.API_V1_STR}/consent/on-notify", "ABDM M3 - Consent Management"),
            (f"{settings.API_V1_STR}/consents/fetch", "ABDM M3 - Consent Management"),
            (f"{settings.API_V1_STR}/consents/on-fetch", "ABDM M3 - Consent Management"),
            (f"{settings.API_V1_STR}/consent/acknowledge", "ABDM M3 - Consent Management"),

            # ABDM M3 - Health Information Exchange
            (f"{settings.API_V1_STR}/health-information/request", "ABDM M3 - Health Information Exchange"),
            (f"{settings.API_V1_STR}/health-information/on-request", "ABDM M3 - Health Information Exchange"),
            (f"{settings.API_V1_STR}/health-information/hip/request", "ABDM M3 - Health Information Exchange"),
            (f"{settings.API_V1_STR}/health-information/transfer", "ABDM M3 - Health Information Exchange"),
            (f"{settings.API_V1_STR}/health-information/data", "ABDM M3 - Health Information Exchange"),
            (f"{settings.API_V1_STR}/health-information/notify", "ABDM M3 - Health Information Exchange"),
            (f"{settings.API_V1_STR}/health-information/cm/notify", "ABDM M3 - Health Information Exchange"),
            (f"{settings.API_V1_STR}/health-information/ack", "ABDM M3 - Health Information Exchange"),

            # M3 Data Fetch
            (f"{settings.API_V1_STR}/health-records", "M3 Data Fetch"),

            # ABDM Admin
            (f"{settings.API_V1_STR}/admin/transactions", "ABDM Admin"),
            (f"{settings.API_V1_STR}/admin/api-logs", "ABDM Admin"),
        ]

        ordered_paths = {}
        processed_paths = set()

        for path, target_tag in ordered_api_specs:
            if path in paths:
                path_item = paths[path]
                for method, operation in path_item.items():
                    if isinstance(operation, dict):
                        operation["tags"] = [target_tag]
                ordered_paths[path] = path_item
                processed_paths.add(path)

        for path, path_item in paths.items():
            if path not in processed_paths and path not in ALIAS_M1_PATHS:
                ordered_paths[path] = path_item

        schema["paths"] = ordered_paths

        ordered_tags = [
            "ABDM M1",
            "ABDM M2 - 1. Gateway & Setup",
            "ABDM M2 - 2. HIP-Initiated Linking",
            "ABDM M2 - 3. User-Initiated Linking",
            "ABDM M2 - 4. Health Data Transfer & Consent",
            "ABDM M2 - 5. Scan & Share",
            "ABDM M3 - Consent Management",
            "ABDM M3 - Health Information Exchange",
            "M3 Data Fetch",
            "ABDM Admin",
        ]
        # Append any other tags dynamically
        for path_item in ordered_paths.values():
            for method, operation in path_item.items():
                if isinstance(operation, dict):
                    for tag in operation.get("tags", []):
                        if tag not in ordered_tags:
                            ordered_tags.append(tag)

        schema["tags"] = [{"name": tag} for tag in ordered_tags]
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi

    return app

# The application instance
app = create_app()
