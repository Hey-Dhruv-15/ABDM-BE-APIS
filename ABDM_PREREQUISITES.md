# ABDM Integration Prerequisites

This document lists everything required before this gateway can successfully integrate with ABDM/ABHA. The list is derived from the current codebase configuration and runtime checks.

## 1. External/Program Enrollment Items (from ABDM)

You must obtain and provision these values through your ABDM/ABHA onboarding process:

- `ABDM_CLIENT_ID` and `ABDM_CLIENT_SECRET` for gateway session token generation.
- `ABDM_CM_ID` (CM identifier; default `sbx` is only a placeholder).
- Registered participant identity:
  - `ABDM_HIP_ID` and/or `ABDM_HIU_ID` (required for M2/M3 flows).
  - `ABDM_PARTICIPANT_ID` + `ABDM_PARTICIPANT_TYPE` if you use a single participant header for general calls.
- Valid callback base URL reachable by ABDM:
  - Used by `GET {ABDM_CALLBACK_BASE_PATH}` for reachability checks.
  - Used by ABDM to send M2/M3 callbacks.

## 2. Network/Region Preconditions

The ABDM routes are blocked unless these conditions are met:

- `ENABLE_ABHA=true`
- `REGION=india`
- Request network resolved as `ABHA` (internally enforced on ABHA routes).

If you run in another region or disable ABHA, ABDM routes will return `403`.

## 3. Required Environment Configuration

These settings must be configured (empty values cause immediate failures):

- Base URL + auth:
  - `ABDM_BASE_URL` (default in code is `https://dev.abdm.gov.in`).
  - `ABDM_AUTH_PATH` (default `/gateway/v0.5/sessions`).
  - `ABDM_CLIENT_ID`
  - `ABDM_CLIENT_SECRET`
  - `ABDM_GRANT_TYPE` (default `client_credentials`).
  - `ABDM_HTTP_TIMEOUT_SECONDS` (optional).
  - `ABDM_TOKEN_REFRESH_SKEW_SECONDS` (optional).

- M1 (ABHA V3) endpoint paths:
  - `ABDM_ABHA_V3_BASE_URL`
  - `ABDM_ABHA_V3_PUBLIC_CERT_PATH`
  - `ABDM_ABHA_V3_SEARCH_PATH`
  - `ABDM_ABHA_V3_LOGIN_REQUEST_OTP_PATH`
  - `ABDM_ABHA_V3_LOGIN_VERIFY_PATH`
  - `ABDM_ABHA_V3_ENROLL_REQUEST_OTP_PATH`
  - `ABDM_ABHA_V3_ENROLL_BY_AADHAAR_PATH`
  - Auto-enroll flow: `POST /api/v1/abha/v3/enrollment/request/otp/auto` (uses public certificate internally)

- M2 (Consent/Health Info) endpoint paths:
  - `ABDM_M2_PATIENT_DISCOVER_PATH`
  - `ABDM_M2_CONSENT_REQUEST_INIT_PATH`
  - `ABDM_M2_CONSENT_STATUS_PATH_TEMPLATE`
  - `ABDM_M2_HEALTH_INFO_REQUEST_PATH`
  - `ABDM_M2_CARE_CONTEXTS_DISCOVER_PATH`
  - `ABDM_M2_CARE_CONTEXTS_LINK_PATH`

- M3 endpoint paths:
  - `ABDM_M3_LINK_TOKEN_INIT_PATH`
  - `ABDM_M3_LINK_TOKEN_CONFIRM_PATH`
  - `ABDM_M3_LINK_CONTEXT_NOTIFY_PATH`
  - `ABDM_M3_PATIENT_PROFILE_SHARE_PATH`

## 3.1 Minimum M2 API Set (Certification Core Flow)

These are the minimum M2 APIs and webhooks required for certification. All paths below are exposed under the API base prefix (default ` /api/v1`).

Auth and bridge setup:
- `POST /hiecm/gateway/v3/sessions` (Auth token)
- `PATCH /hiecm/gateway/v3/bridge/url` (Register bridge/webhook URL)

HIP linking flow:
- `POST /hiecm/v3/token/generate-token` (Generate link token)
- `POST /v3/hip/token/on-generate-token` (Token callback)
- `POST /hiecm/hip/v3/link/carecontext` (Link care context)
- `POST /v3/hip/link/on-care-context` (Link confirmation callback)

Consent flow:
- `POST /consent/notification` or `POST /consent/notify` (Consent notify callback)
- `POST /consent/acknowledge` (Consent acknowledge to ABDM if required; outbound from your system)

Data flow:
- `POST /health-information/request` (Data request callback)
- `POST /health-information/ack` (Ack data request to ABDM if required; outbound from your system)
- `POST /health-information/data` (Push data to ABDM; outbound from your system)
- `POST /health-information/notify` (Delivery notify callback)

Note: outbound calls (acknowledge/data) are initiated by your system to ABDM. This gateway exposes proxy routes for them, but you must configure:
- `ABDM_M2_CONSENT_ACK_PATH`
- `ABDM_M2_HEALTH_INFO_ACK_PATH`
- `ABDM_M2_HEALTH_INFO_DATA_PATH`

## 4. Callback Authentication & Security

Callback validation is controlled by `ABDM_CALLBACK_AUTH_MODE`:

- `none`: no validation.
- `ip`: validate request source IP with `ABDM_CALLBACK_IP_WHITELIST`.
- `hmac`: validate `X-HMAC-SIGNATURE` and `X-HMAC-TIMESTAMP` headers using `ABDM_CALLBACK_HMAC_SECRET`.
- `hmac_ip`: both checks.

If `hmac` is enabled, you must configure:

- `ABDM_CALLBACK_HMAC_SECRET`
- `ABDM_CALLBACK_HMAC_TOLERANCE_SECONDS` (default 300s)

If `ip` is enabled, you must configure:

- `ABDM_CALLBACK_IP_WHITELIST` (comma-separated list)

## 5. Optional Deployment Lock (Strongly Recommended)

When `ENFORCE_NETWORK_LOCK=true`, the service checks:

- `ABDM_EXPECTED_CLIENT_ID`
- `ABDM_EXPECTED_BASE_URL`

If they do not match configured values, ABDM auth is blocked to prevent cross-environment credential misuse.

## 6. Gateway Access Authentication (Inbound)

The ABDM routes are under the gateway’s normal auth/security controls:

- `REQUIRE_AUTHORIZATION_HEADER`
- `REQUIRE_JWT_VALIDATION`
- `JWT_SECRET` or `JWT_PUBLIC_KEY_PEM`
- `JWT_EXPECTED_ISSUER` and `JWT_EXPECTED_AUDIENCE`

If these are enabled, callers must provide valid authorization to reach ABDM endpoints.

## 7. Orchestration State Storage (Callbacks)

ABHA callback workflows are persisted via the orchestration store:

- If `ORCHESTRATION_REDIS_URL` is set, state is stored in Redis.
- If not set, an in-memory fallback is used.

Redis is optional but recommended for multi-instance or production deployments.

## 8. Outbound Connectivity & Certificates

The gateway must be able to reach:

- `ABDM_BASE_URL` over HTTPS
- Any data push URLs you send in consent/health-info flows

If your environment requires outbound proxy/TLS pinning, configure at the infrastructure layer.

## 9. Quick Readiness Check

Once configured, you can confirm local readiness using:

- `GET /api/v1/abdm/status`
- `GET /api/v1/abdm/m1/heartbeat`
- `GET /api/v1{ABDM_CALLBACK_BASE_PATH}`

These endpoints report missing values or connectivity issues early.

## 10. Error Behavior / Failure Modes

Common runtime errors you should expect and handle:

- Missing path config → `503` with “not configured”
- Disabled ABHA or wrong region → `403`
- Missing HMAC/IP config when enabled → `503`
