"""
Core application settings management using Pydantic.
"""
from typing import Dict, List, Set
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""
    
    # Application Info
    PROJECT_NAME: str = "Interop Gateway"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    REGION: str = "india"
    
    # Configuration Path
    CONFIG_PATH: str = "app/config/integrations"
    CONFIG_WATCH_ENABLED: bool = True
    
    # Logging
    LOG_LEVEL: str = "INFO"

    # Security
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION"
    CORS_ORIGINS: List[str] = ["*"]
    REQUIRE_AUTHORIZATION_HEADER: bool = True
    ENFORCE_REGION_HEADER: bool = True
    SECURITY_ENFORCED_PREFIX: str = "/api/v1"
    ALLOWED_SOURCE_IPS: str = ""

    # Integration Resolver
    ENABLE_ABHA: bool = True
    ENABLE_NABIDH: bool = False
    ENABLED_NETWORKS: str = "ABHA,NABIDH"
    REGION_NETWORK_MAP: str = (
        "india:ABHA,uae:NABIDH,uk:NHS_SPINE,australia:MY_HEALTH_RECORD,"
        "usa:EHEALTH_EXCHANGE,canada:CANADA_HEALTH_INFOWAY,singapore:NEHR,"
        "finland:KANTA,denmark:DANISH_NHDN"
    )

    # ABDM M1
    ABDM_BASE_URL: str = "https://dev.abdm.gov.in"
    ABDM_AUTH_PATH: str = "/api/hiecm/gateway/v3/sessions"
    ABDM_CLIENT_ID: str = ""
    ABDM_CLIENT_SECRET: str = ""
    ABDM_GRANT_TYPE: str = "client_credentials"
    ABDM_CM_ID: str = "sbx"
    ABDM_INTEGRATION_ID: str = "test-relay"
    ABDM_PARTICIPANT_ID: str = ""
    ABDM_PARTICIPANT_TYPE: str = "HIP"
    ABDM_CALLBACK_BASE_PATH: str = "/abdm/m1/callback"
    ABDM_CALLBACK_AUTH_MODE: str = "none"  # none|hmac|ip|hmac_ip
    ABDM_CALLBACK_HMAC_SECRET: str = ""
    ABDM_CALLBACK_HMAC_TOLERANCE_SECONDS: int = 300
    ABDM_CALLBACK_IP_WHITELIST: str = ""
    ABDM_HEADER_TIMESTAMP_TOLERANCE_SECONDS: int = 300
    ABDM_HTTP_TIMEOUT_SECONDS: float = 15.0
    ABDM_HTTP_RETRY_ATTEMPTS: int = 2
    ABDM_TOKEN_REFRESH_SKEW_SECONDS: int = 120
    ABDM_ABHA_GENERATE_OTP_PATH: str = "/v1/registration/aadhaar/generateOtp"
    ABDM_ABHA_VERIFY_OTP_PATH: str = "/v1/registration/aadhaar/verifyOTP"
    ABDM_ABHA_CREATE_ADDRESS_PATH: str = "/v1/registration/aadhaar/createHealthIdWithPreVerified"
    ABDM_ABHA_CREATE_NUMBER_PATH: str = ""
    ABDM_ABHA_GENERATE_MOBILE_OTP_PATH: str = "/v1/registration/aadhaar/generateMobileOTP"
    ABDM_ABHA_VERIFY_MOBILE_OTP_PATH: str = "/v1/registration/aadhaar/verifyMobileOTP"
    ABDM_ABHA_CHANGE_MOBILE_NEW_GENERATE_OTP_PATH: str = "/v2/account/change/mobile/new/generateOTP"
    ABDM_ABHA_CHANGE_MOBILE_NEW_VERIFY_OTP_PATH: str = "/v2/account/change/mobile/new/verifyOTP"
    ABDM_ABHA_CHANGE_MOBILE_AADHAAR_GENERATE_OTP_PATH: str = "/v2/account/change/mobile/aadhaar/generateOTP"
    ABDM_ABHA_CHANGE_MOBILE_OLD_GENERATE_OTP_PATH: str = "/v2/account/change/mobile/old/generateOTP"
    ABDM_ABHA_CHANGE_MOBILE_UPDATE_AUTH_PATH: str = "/v2/account/change/mobile/update/authentication"
    ABDM_ABHA_CHECK_ADDRESS_PATH: str = ""
    ABDM_ABHA_PROFILE_GET_PATH: str = ""
    ABDM_ABHA_PROFILE_UPDATE_PATH: str = ""
    ABDM_ABHA_LOGIN_INIT_PATH: str = ""
    ABDM_ABHA_LOGIN_CONFIRM_PATH: str = ""
    ABDM_ABHA_AUTO_ADD_CONSENT: bool = True
    ABDM_ABHA_CONSENT_CODE: str = "abha-enrollment"
    ABDM_ABHA_CONSENT_VERSION: str = "1.4"
    ABDM_ABHA_V3_BASE_URL: str = "https://abhasbx.abdm.gov.in"
    ABDM_ABHA_V3_PUBLIC_CERT_PATH: str = "/abha/api/v3/profile/public/certificate"
    ABDM_ABHA_V3_SEARCH_PATH: str = "/abha/api/v3/profile/account/abha/search"
    ABDM_ABHA_V3_LOGIN_REQUEST_OTP_PATH: str = "/abha/api/v3/profile/login/request/otp"
    ABDM_ABHA_V3_LOGIN_VERIFY_PATH: str = "/abha/api/v3/profile/login/verify"
    ABDM_ABHA_V3_LOGIN_VERIFY_USER_PATH: str = "/abha/api/v3/profile/login/verify/user"
    ABDM_ABHA_V3_ENROLL_REQUEST_OTP_PATH: str = "/abha/api/v3/enrollment/request/otp"
    ABDM_ABHA_V3_ENROLL_BY_AADHAAR_PATH: str = "/abha/api/v3/enrollment/enrol/byAadhaar"
    ABDM_ABHA_V3_ENROLL_AUTH_BY_ABDM_PATH: str = "/abha/api/v3/enrollment/auth/byAbdm"
    ABDM_ABHA_V3_ADDRESS_SUGGESTIONS_PATH: str = "/abha/api/v3/enrollment/enrol/suggestion"
    ABDM_ABHA_V3_CREATE_PHR_ADDRESS_PATH: str = "/abha/api/v3/enrollment/enrol/abha-address"
    ABDM_ABHA_V3_ACCOUNT_REQUEST_OTP_PATH: str = "/abha/api/v3/profile/account/request/otp"
    ABDM_ABHA_V3_ACCOUNT_VERIFY_PATH: str = "/abha/api/v3/profile/account/verify"
    ABDM_ABHA_V3_ABHA_CARD_PATH: str = "/abha/api/v3/profile/account/abha-card"
    ABDM_ABHA_V3_ENROL_SUGGESTIONS_GET_PATH: str = "/abha/api/v3/enrollment/enrol/suggestion"
    ABDM_ABHA_V3_ENROL_ADDRESS_PATH: str = "/abha/api/v3/enrollment/enrol/abha-address"
    ABDM_ABHA_V3_ACCOUNT_CARD_PATH: str = "/abha/api/v3/profile/account/abha-card"
    ABDM_ABHA_V3_ACCOUNT_PROFILE_PATH: str = "/abha/api/v3/profile/account"
    ABDM_ABHA_V3_ACCOUNT_QR_CODE_PATH: str = "/abha/api/v3/profile/account/qrCode"
    ABDM_HPR_BASE_URL: str = "https://apihspsbx.abdm.gov.in"
    ABDM_HPR_API_PREFIX: str = "/v4/int/apis/v1"
    ABDM_HPR_REGISTRATION_PREFIX: str = "/v4/int/v2"
    ABDM_HPR_MASTER_DATA_PREFIX: str = "/v4/int/apis/v1"
    ABDM_HPR_PUBLIC_CERT_PATH: str = "/v4/int/v2/auth/cert"

    # Deployment lock (prevents cross-environment credential use)
    HEALTH_NETWORK: str = "ABHA"  # e.g. ABHA or NABIDH
    ENFORCE_NETWORK_LOCK: bool = True
    ABDM_EXPECTED_CLIENT_ID: str = ""
    ABDM_EXPECTED_BASE_URL: str = ""

    # ABDM M2 - Participant identities
    ABDM_HIP_ID: str = ""
    ABDM_HIU_ID: str = ""
    ABDM_FACILITY_ID: str = ""

    # ABDM M2 - Endpoint paths
    ABDM_M2_OPENID_CONFIG_PATH: str = "/api/hiecm/gateway/v3/.well-known/openid-configuration"
    ABDM_M2_CERTS_PATH: str = "/api/hiecm/gateway/v3/certs"
    ABDM_M2_BRIDGE_URL_PATH: str = "/api/hiecm/gateway/v3/bridge/url"
    ABDM_M2_BRIDGE_SERVICE_BY_ID_PATH: str = "/api/hiecm/gateway/v3/bridge-service/serviceId/{serviceId}"
    ABDM_M2_BRIDGE_SERVICES_PATH: str = "/api/hiecm/gateway/v3/bridge-services"
    ABDM_HSP_BASE_URL: str = "https://apihspsbx.abdm.gov.in"
    ABDM_M2_BRIDGE_SERVICES_UPDATE_PATH: str = "/v4/int/v1/bridges/MutipleHRPAddUpdateServices"
    ABDM_M2_LINK_TOKEN_GENERATE_PATH: str = "/api/hiecm/v3/token/generate-token"
    ABDM_M2_LINK_CARE_CONTEXT_PATH: str = "/api/hiecm/hip/v3/link/carecontext"
    ABDM_M2_LINK_CONTEXT_NOTIFY_PATH: str = "/api/hiecm/hip/v3/link/context/notify"
    # Legacy M2 paths retained for internal gateway flows (deprecated).
    ABDM_M2_SESSIONS_PATH: str = "/gateway/v0.5/sessions"
    ABDM_M2_PATIENT_DISCOVER_PATH: str = "/gateway/v0.5/patients/discover"
    ABDM_M2_CONSENT_REQUEST_INIT_PATH: str = "/gateway/v0.5/consent-requests/init"
    ABDM_M2_CONSENT_STATUS_PATH_TEMPLATE: str = "/gateway/v0.5/consents/{consent_id}"
    ABDM_M2_CARE_CONTEXTS_DISCOVER_PATH: str = "/api/hiecm/user-initiated-linking/v3/patient/care-context/on-discover"
    ABDM_M2_CARE_CONTEXTS_LINK_PATH: str = "/api/hiecm/user-initiated-linking/v3/link/care-context/on-init"
    ABDM_M2_CARE_CONTEXTS_CONFIRM_PATH: str = "/api/hiecm/user-initiated-linking/v3/link/care-context/on-confirm"
    ABDM_M2_HEALTH_INFO_ACK_PATH: str = ""
    ABDM_M2_HEALTH_INFO_DATA_PATH: str = ""

    # ABDM M3 - HIU certification endpoint paths (official ABDM v3 Gateway spec)
    ABDM_M3_SESSIONS_PATH: str = "/api/hiecm/gateway/v3/sessions"
    ABDM_M3_CONSENT_REQUEST_INIT_PATH: str = "/api/hiecm/consent/v3/request/init"
    ABDM_M3_CONSENT_FETCH_PATH: str = "/api/hiecm/consent/v3/fetch"
    ABDM_M3_HEALTH_INFO_REQUEST_PATH: str = "/api/hiecm/data-flow/v3/health-information/request"
    ABDM_M3_HEALTH_INFO_CM_NOTIFY_PATH: str = "/api/hiecm/data-flow/v3/health-information/notify"

    # ABDM M3 - Endpoint paths (configurable; defaults follow common gateway contracts)
    ABDM_M3_LINK_TOKEN_INIT_PATH: str = "/gateway/v0.5/links/link/token/init"
    ABDM_M3_LINK_TOKEN_CONFIRM_PATH: str = "/gateway/v0.5/links/link/token/confirm"
    ABDM_M3_LINK_CONTEXT_NOTIFY_PATH: str = "/gateway/v0.5/links/context/notify"
    ABDM_M3_PATIENT_PROFILE_SHARE_PATH: str = "/gateway/v0.5/patients/profile/share"
    ABDM_M3_PATIENT_SHARE_ON_SHARE_PATH: str = "/api/hiecm/patient-share/v3/on-share"
    ABDM_M2_SCAN_SHARE_QR_BASE_URL: str = "https://phrsbx.abdm.gov.in/phr/v3/share-profile"
    ABDM_M3_SCAN_SHARE_QR_BASE_URL: str = "https://phrsbx.abdm.gov.in/phr/v3/share-profile"
    ABDM_M3_PATIENTS_COLLECTION: str = "abdm_m3_patients"
    ABDM_M3_TOKEN_EXPIRY_SECONDS: int = 180

    # ABDM M3 - Consent Flow v3 paths (per ABDM M3 Documentation §4)
    ABDM_M3_CONSENT_V3_REQUEST_INIT_PATH: str = "/api/hiecm/consent/v3/request/init"
    ABDM_M3_CONSENT_V3_STATUS_PATH: str = "/api/hiecm/consent/v3/request/status"
    ABDM_M3_CONSENT_V3_FETCH_PATH: str = "/api/hiecm/consent/v3/fetch"

    # ABDM M3 - Data Flow v3 paths (per ABDM M3 Documentation §5)
    ABDM_M3_DATA_FLOW_V3_REQUEST_PATH: str = "/api/hiecm/data-flow/v3/health-information/request"

    # NABIDH
    NABIDH_BASE_URL: str = "https://api.nabidh.ae"
    NABIDH_AUTH_PATH: str = "/oauth2/token"
    NABIDH_CLIENT_ID: str = ""
    NABIDH_CLIENT_SECRET: str = ""
    NABIDH_SCOPE: str = ""
    NABIDH_GRANT_TYPE: str = "client_credentials"
    NABIDH_HTTP_TIMEOUT_SECONDS: float = 15.0
    NABIDH_TOKEN_REFRESH_SKEW_SECONDS: int = 120
    NABIDH_FHIR_BASE_PATH: str = "/fhir"

    # Gateway orchestration defaults
    ABDM_BRIDGE_URL: str | None = None
    GATEWAY_DEFAULT_DATA_PUSH_URL: str = "https://yourserver.com/health-data"
    ORCHESTRATION_REDIS_URL: str = ""
    ORCHESTRATION_STATE_TTL_SECONDS: int = 86400

    # Twilio SMS Service Configuration
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_PHONE_NUMBER: str = ""
    TWILIO_VERIFY_SERVICE_SID: str = ""

    # Fast2SMS Configuration
    FAST2SMS_API_KEY: str = ""


    ENABLE_MONGODB: bool = False
    MONGODB_URI: str = "mongodb://localhost:27017/"
    MONGODB_DB_NAME: str = "gateway"
    MONGODB_SERVER_SELECTION_TIMEOUT_MS: int = 1000
    ABDM_LINKED_CARE_CONTEXTS_COLLECTION: str = "linked_care_contexts"
    ABDM_CONSENTS_COLLECTION: str = "abdm_consents"
    ABDM_LINKAGE_MONGO_ENABLED: bool = False

    # JWT validation for gateway entry auth
    REQUIRE_JWT_VALIDATION: bool = True
    JWT_SECRET: str = ""
    JWT_PUBLIC_KEY_PEM: str = ""
    JWT_EXPECTED_ISSUER: str = ""
    JWT_EXPECTED_AUDIENCE: str = ""

    # model_config provides the rules for how settings are loaded
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    def enabled_networks_set(self) -> Set[str]:
        """Return enabled networks from comma-separated env value."""
        return {item.strip().upper() for item in self.ENABLED_NETWORKS.split(",") if item.strip()}

    def region_network_map_dict(self) -> Dict[str, str]:
        """Parse region->network map from comma-separated key:value entries."""
        mapping: Dict[str, str] = {}
        for item in self.REGION_NETWORK_MAP.split(","):
            entry = item.strip()
            if not entry or ":" not in entry:
                continue
            region, network = entry.split(":", 1)
            mapping[region.strip().lower()] = network.strip().upper()
        return mapping

    def is_network_enabled(self, network: str) -> bool:
        """Determine if a network is enabled in this deployment."""
        normalized = network.strip().upper()
        if normalized == "ABHA" and not self.ENABLE_ABHA:
            return False
        if normalized == "NABIDH" and not self.ENABLE_NABIDH:
            return False
        enabled = self.enabled_networks_set()
        return normalized in enabled if enabled else False

settings = Settings()
