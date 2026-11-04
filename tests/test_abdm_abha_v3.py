import pytest
from httpx import ASGITransport, AsyncClient

from app.api.dependencies import set_abdm_gateway_client
import app.api.routes.abdm as abdm_routes
from app.main import create_app
from app.settings import settings


class StubABDMGatewayClient:
    def __init__(
        self,
        post_responses: list[dict] | None = None,
        get_responses: list[dict] | None = None,
    ) -> None:
        self.calls: list[dict] = []
        self.post_responses = list(post_responses or [])
        self.get_responses = list(get_responses or [])

    async def post(
        self,
        path: str,
        body: dict,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: dict | None = None,
        include_cm_header: bool = True,
        include_auth_header: bool = True,
    ) -> dict:
        self.calls.append(
            {
                "path": path,
                "body": body,
                "include_participant_header": include_participant_header,
                "participant_id": participant_id,
                "participant_type": participant_type,
                "base_url": base_url,
                "extra_headers": extra_headers or {},
                "include_cm_header": include_cm_header,
            }
        )
        if self.post_responses:
            return self.post_responses.pop(0)
        return {"status": "ok"}

    async def get(
        self,
        path: str,
        include_participant_header: bool = True,
        participant_id: str | None = None,
        participant_type: str | None = None,
        base_url: str | None = None,
        extra_headers: dict | None = None,
        include_cm_header: bool = True,
    ) -> dict:
        self.calls.append(
            {
                "path": path,
                "body": None,
                "include_participant_header": include_participant_header,
                "participant_id": participant_id,
                "participant_type": participant_type,
                "base_url": base_url,
                "extra_headers": extra_headers or {},
                "include_cm_header": include_cm_header,
            }
        )
        if path == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH:
            return {"publicKey": "TEST_PUBLIC_KEY", "encryptionAlgorithm": "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"}
        if self.get_responses:
            return self.get_responses.pop(0)
        return {"status": "ok"}


def _configure_test_settings() -> None:
    settings.ENFORCE_REGION_HEADER = False
    settings.REQUIRE_AUTHORIZATION_HEADER = False
    settings.REQUIRE_JWT_VALIDATION = False
    settings.ENABLE_ABHA = True
    settings.REGION = "india"
    settings.ABDM_ABHA_V3_BASE_URL = "https://abhasbx.abdm.gov.in"
    settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH = "/abha/api/v3/profile/public/certificate"
    settings.ABDM_ABHA_V3_SEARCH_PATH = "/abha/api/v3/profile/account/abha/search"
    settings.ABDM_ABHA_V3_LOGIN_REQUEST_OTP_PATH = "/abha/api/v3/profile/login/request/otp"
    settings.ABDM_ABHA_V3_LOGIN_VERIFY_PATH = "/abha/api/v3/profile/login/verify"
    settings.ABDM_ABHA_V3_ENROLL_REQUEST_OTP_PATH = "/abha/api/v3/enrollment/request/otp"
    settings.ABDM_ABHA_V3_ENROLL_BY_AADHAAR_PATH = "/abha/api/v3/enrollment/enrol/byAadhaar"
    settings.ABDM_ABHA_V3_ENROLL_AUTH_BY_ABDM_PATH = "/abha/api/v3/enrollment/auth/byAbdm"
    settings.ABDM_ABHA_V3_ADDRESS_SUGGESTIONS_PATH = "/abha/api/v3/enrollment/enrol/suggestion"
    settings.ABDM_ABHA_V3_CREATE_PHR_ADDRESS_PATH = "/abha/api/v3/enrollment/enrol/phr-address"
    settings.ABDM_ABHA_V3_ACCOUNT_REQUEST_OTP_PATH = "/abha/api/v3/profile/account/request/otp"
    settings.ABDM_ABHA_V3_ACCOUNT_VERIFY_PATH = "/abha/api/v3/profile/account/verify"
    settings.ABDM_ABHA_V3_ABHA_CARD_PATH = "/abha/api/v3/profile/account/abha-card"
    settings.ABDM_ABHA_V3_ENROL_SUGGESTIONS_GET_PATH = "/abha/api/v3/enrollment/enrol/suggestion"
    settings.ABDM_ABHA_V3_ENROL_ADDRESS_PATH = "/abha/api/v3/enrollment/enrol/abha-address"
    settings.ABDM_ABHA_V3_ACCOUNT_CARD_PATH = "/abha/api/v3/account/card"
    settings.ABDM_ABHA_GENERATE_OTP_PATH = "/v1/registration/aadhaar/generateOtp"
    settings.ABDM_ABHA_VERIFY_OTP_PATH = "/v1/registration/aadhaar/verifyOTP"
    settings.ABDM_ABHA_GENERATE_MOBILE_OTP_PATH = "/v1/registration/aadhaar/generateMobileOTP"
    settings.ABDM_ABHA_VERIFY_MOBILE_OTP_PATH = "/v1/registration/aadhaar/verifyMobileOTP"
    settings.ABDM_ABHA_CREATE_ADDRESS_PATH = "/v1/registration/aadhaar/createHealthIdWithPreVerified"
    settings.ABDM_ABHA_CHANGE_MOBILE_NEW_GENERATE_OTP_PATH = "/v2/account/change/mobile/new/generateOTP"
    settings.ABDM_ABHA_CHANGE_MOBILE_NEW_VERIFY_OTP_PATH = "/v2/account/change/mobile/new/verifyOTP"
    settings.ABDM_ABHA_CHANGE_MOBILE_AADHAAR_GENERATE_OTP_PATH = "/v2/account/change/mobile/aadhaar/generateOTP"
    settings.ABDM_ABHA_CHANGE_MOBILE_OLD_GENERATE_OTP_PATH = "/v2/account/change/mobile/old/generateOTP"
    settings.ABDM_ABHA_CHANGE_MOBILE_UPDATE_AUTH_PATH = "/v2/account/change/mobile/update/authentication"


@pytest.mark.asyncio
async def test_abha_v3_search_forwards_headers_and_base_url() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {"scope": ["search-abha"], "mobile": "RSA Encrypted Mobile Number"}
    headers = {
        "REQUEST-ID": "req-123",
        "TIMESTAMP": "2024-04-21T07:22:06.682Z",
        "BENEFIT_NAME": "benefit-name",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/profile/account/abha/search",
            json=payload,
            headers=headers,
        )

    assert response.status_code == 200
    assert stub.calls
    call = stub.calls[0]
    assert call["path"] == settings.ABDM_ABHA_V3_SEARCH_PATH
    assert call["base_url"] == settings.ABDM_ABHA_V3_BASE_URL
    assert call["include_participant_header"] is False
    assert call["include_cm_header"] is True
    assert call["extra_headers"]["REQUEST-ID"] == headers["REQUEST-ID"]
    assert call["extra_headers"]["TIMESTAMP"] == headers["TIMESTAMP"]
    assert call["extra_headers"]["BENEFIT_NAME"] == headers["BENEFIT_NAME"]
    assert call["body"] == payload


@pytest.mark.asyncio
async def test_abha_v3_search_normalizes_mobile_with_country_code() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/profile/account/abha/search",
                json={"scope": ["search-abha"], "mobile": "+919483512312"},
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp

    assert response.status_code == 200
    assert len(stub.calls) == 2
    assert stub.calls[1]["body"]["mobile"] == "encrypted-9483512312"


@pytest.mark.asyncio
async def test_abdm_status_uses_abha_v3_m1_paths() -> None:
    _configure_test_settings()
    settings.ABDM_CLIENT_ID = "client-id"
    settings.ABDM_CLIENT_SECRET = "client-secret"
    settings.ABDM_CM_ID = "sbx"
    settings.ABDM_HIP_ID = "hip-id"
    settings.ABDM_HIU_ID = "hiu-id"
    settings.ABDM_ABHA_CREATE_NUMBER_PATH = ""
    app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"{settings.API_V1_STR}/abdm/status")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["m1"]["ready"] is True
    assert body["m1"]["missing_paths"] == []


@pytest.mark.asyncio
async def test_abha_v3_login_request_otp_forwards_payload() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {
        "scope": ["abha-login", "search-abha", "mobile-verify"],
        "loginHint": "index",
        "loginId": "RSA encrypted Index Number",
        "otpSystem": "abdm",
        "txnId": "txn-123",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/profile/login/request/otp",
            json=payload,
        )

    assert response.status_code == 200
    assert stub.calls
    call = stub.calls[0]
    assert call["path"] == settings.ABDM_ABHA_V3_LOGIN_REQUEST_OTP_PATH
    assert call["body"] == payload


@pytest.mark.asyncio
async def test_abha_v3_login_request_otp_encrypts_plain_index_login_id() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    try:
        payload = {
            "scope": ["abha-login", "search-abha", "mobile-verify"],
            "loginHint": "index",
            "loginId": "9483512312",
            "otpSystem": "abdm",
            "txnId": "txn-123",
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/profile/login/request/otp",
                json=payload,
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt

    assert response.status_code == 200
    assert len(stub.calls) == 2
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_LOGIN_REQUEST_OTP_PATH
    assert stub.calls[1]["body"]["loginId"] == "encrypted-9483512312"


@pytest.mark.asyncio
async def test_abha_v3_login_request_otp_does_not_override_gateway_authorization() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {
        "scope": ["abha-login", "search-abha", "mobile-verify"],
        "loginHint": "index",
        "loginId": "already-encrypted-login-id",
        "otpSystem": "abdm",
        "txnId": "txn-123",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/profile/login/request/otp",
            json=payload,
            headers={"Authorization": "Bearer caller-token"},
        )

    assert response.status_code == 200
    assert "Authorization" not in stub.calls[0]["extra_headers"]


@pytest.mark.asyncio
async def test_abha_v3_login_verify_forwards_payload() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {
        "scope": ["abha-login", "mobile-verify"],
        "authData": {"authMethods": ["otp"], "otp": {"txnId": "txn-1", "otpValue": "enc-otp", "timeStamp": "2026-08-06T10:00:00.000Z"}},
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/profile/login/verify",
            json=payload,
        )

    assert response.status_code == 200
    assert stub.calls
    call = stub.calls[0]
    assert call["path"] == settings.ABDM_ABHA_V3_LOGIN_VERIFY_PATH
    assert call["body"] == payload


@pytest.mark.asyncio
async def test_abha_v3_public_certificate_get() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.get(
            f"{settings.API_V1_STR}/abha/v3/profile/public/certificate",
            headers={
                "REQUEST-ID": "req-1",
                "TIMESTAMP": "2024-04-21T07:22:06.682Z",
                "Authorization": "Bearer caller-token",
            },
        )

    assert response.status_code == 200
    assert stub.calls
    call = stub.calls[0]
    assert call["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert call["base_url"] == settings.ABDM_ABHA_V3_BASE_URL
    assert call["include_participant_header"] is False
    assert call["include_cm_header"] is True
    assert "Authorization" not in call["extra_headers"]


@pytest.mark.asyncio
async def test_abha_v3_enroll_request_otp_forwards_payload() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {
        "txnId": "",
        "scope": ["abha-enrol"],
        "loginHint": "aadhaar",
        "loginId": "ENCRYPTED_AADHAAR",
        "otpSystem": "aadhaar",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/enrollment/request/otp",
            json=payload,
        )

    assert response.status_code == 200
    assert stub.calls
    call = stub.calls[0]
    assert call["path"] == settings.ABDM_ABHA_V3_ENROLL_REQUEST_OTP_PATH
    assert call["body"] == payload


@pytest.mark.asyncio
async def test_abha_v3_enroll_request_otp_encrypts_plain_mobile() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/enrollment/request/otp",
                json={
                    "txnId": "aadhaar-enrol-txn-id",
                    "scope": ["abha-enrol", "mobile-verify"],
                    "loginHint": "mobile",
                    "loginId": "+919483512312",
                    "otpSystem": "abdm",
                },
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt

    assert response.status_code == 200
    assert len(stub.calls) == 2
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_ENROLL_REQUEST_OTP_PATH
    assert stub.calls[1]["body"] == {
        "txnId": "aadhaar-enrol-txn-id",
        "scope": ["abha-enrol", "mobile-verify"],
        "loginHint": "mobile",
        "loginId": "encrypted-9483512312",
        "otpSystem": "abdm",
    }


@pytest.mark.asyncio
async def test_abha_v3_enroll_by_aadhaar_encrypts_plain_otp_and_normalizes_mobile() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {
        "authData": {
            "authMethods": ["otp"],
            "otp": {"txnId": "txn-1", "otpValue": "123456", "mobile": "+919876543210"},
        },
        "consent": {"code": "abha-enrollment", "version": "1.4"},
    }

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/enrollment/enrol/byAadhaar",
                json=payload,
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp

    assert response.status_code == 200
    assert len(stub.calls) == 2
    call = stub.calls[1]
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert call["path"] == settings.ABDM_ABHA_V3_ENROLL_BY_AADHAAR_PATH
    assert call["body"] == {
        "authData": {
            "authMethods": ["otp"],
            "otp": {"txnId": "txn-1", "otpValue": "encrypted-123456", "mobile": "9876543210"},
        },
        "consent": {"code": "abha-enrollment", "version": "1.4"},
    }


@pytest.mark.asyncio
async def test_abha_v3_enroll_request_otp_auto_encrypts_and_calls() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    abdm_routes.encrypt_abha_value = lambda value, public_key: "ENCRYPTED_AADHAAR"
    try:
        payload = {"aadhaar": "214253253526"}
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/enrollment/request/otp/auto",
                json=payload,
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt

    assert response.status_code == 200
    assert len(stub.calls) == 2
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_ENROLL_REQUEST_OTP_PATH
    assert stub.calls[1]["body"]["loginId"] == "ENCRYPTED_AADHAAR"


@pytest.mark.asyncio
async def test_abha_v3_enrollment_auth_by_abdm_forwards_payload() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {
        "scope": ["abha-enrol", "mobile-verify"],
        "authData": {
            "authMethods": ["otp"],
            "otp": {
                "txnId": "mobile-otp-txn-id",
                "otpValue": "ENCRYPTED_OTP",
                "timeStamp": "2026-05-29T10:30:00.000Z",
            },
        },
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/enrollment/auth/byAbdm",
            json=payload,
            headers={"X-token": "enrollment-access-token"},
        )

    assert response.status_code == 200
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_ENROLL_AUTH_BY_ABDM_PATH
    assert stub.calls[0]["base_url"] == settings.ABDM_ABHA_V3_BASE_URL
    assert stub.calls[0]["body"] == payload
    assert stub.calls[0]["extra_headers"]["X-token"] == "enrollment-access-token"


@pytest.mark.asyncio
async def test_abha_v3_enrollment_auth_by_abdm_encrypts_plain_otp() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        abdm_routes.ABHA_ENROLLMENT_TOKENS["mobile-otp-txn-id"] = {
            "token": "enrollment-access-token",
            "expires_at": None,
            "stored_at": 0,
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/enrollment/auth/byAbdm",
                json={
                    "scope": ["abha-enrol", "mobile-verify"],
                    "authData": {
                        "authMethods": ["otp"],
                        "otp": {"txnId": "mobile-otp-txn-id", "otpValue": "123456"},
                    },
                },
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp
        abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()

    assert response.status_code == 200
    assert len(stub.calls) == 2
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_ENROLL_AUTH_BY_ABDM_PATH
    assert stub.calls[1]["body"]["authData"]["otp"]["otpValue"] == "encrypted-123456"
    assert stub.calls[1]["body"]["authData"]["otp"]["timeStamp"].endswith("Z")
    assert stub.calls[1]["extra_headers"]["X-token"] == "enrollment-access-token"


@pytest.mark.asyncio
async def test_abha_v3_enrollment_auth_by_abdm_requires_enrollment_token() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()
    abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/enrollment/auth/byAbdm",
            json={
                "scope": ["abha-enrol", "mobile-verify"],
                "authData": {
                    "authMethods": ["otp"],
                    "otp": {"txnId": "mobile-otp-txn-id", "otpValue": "ENCRYPTED_OTP"},
                },
            },
        )

    assert response.status_code == 401
    assert stub.calls == []


@pytest.mark.asyncio
async def test_abha_v3_enrollment_mobile_flow_reuses_stored_enrollment_token() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient(
        post_responses=[
            {"txnId": "enrollment-txn-id", "tokens": {"token": "enrollment-access-token"}},
            {"txnId": "mobile-otp-txn-id"},
            {"status": "ok"},
        ]
    )
    app = create_app()
    abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            enroll_response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/enrollment/enrol/byAadhaar",
                json={
                    "authData": {
                        "authMethods": ["otp"],
                        "otp": {"txnId": "aadhaar-otp-txn-id", "otpValue": "ENCRYPTED_OTP", "mobile": "9876543210"},
                    },
                    "consent": {"code": "abha-enrollment", "version": "1.4"},
                },
            )
            mobile_response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/enrollment/request/mobile-otp",
                json={
                    "txnId": "enrollment-txn-id",
                    "scope": ["abha-enrol", "mobile-verify"],
                    "loginHint": "mobile",
                    "loginId": "9876543210",
                    "otpSystem": "abdm",
                },
            )
            auth_response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/enrollment/auth/byAbdm",
                json={
                    "scope": ["abha-enrol", "mobile-verify"],
                    "authData": {
                        "authMethods": ["otp"],
                        "otp": {"txnId": "mobile-otp-txn-id", "otpValue": "123456"},
                    },
                },
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp
        abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()

    assert [enroll_response.status_code, mobile_response.status_code, auth_response.status_code] == [200, 200, 200]
    mobile_otp_call = stub.calls[2]
    auth_call = stub.calls[4]
    assert mobile_otp_call["path"] == settings.ABDM_ABHA_V3_ENROLL_REQUEST_OTP_PATH
    assert mobile_otp_call["extra_headers"]["X-token"] == "enrollment-access-token"
    assert auth_call["path"] == settings.ABDM_ABHA_V3_ENROLL_AUTH_BY_ABDM_PATH
    assert auth_call["extra_headers"]["X-token"] == "enrollment-access-token"
    assert auth_call["body"]["authData"]["otp"]["otpValue"] == "encrypted-123456"
    assert auth_call["body"]["authData"]["otp"]["txnId"] == "mobile-otp-txn-id"


@pytest.mark.asyncio
async def test_abha_v3_address_and_card_endpoints_forward_payloads() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        suggestions_response = await client.post(
            f"{settings.API_V1_STR}/v3/enrollment/abha-address/suggestions",
            json={"txnId": "abha-creation-txn-id"},
            headers={"X-token": "enrollment-token"},
        )
        create_response = await client.post(
            f"{settings.API_V1_STR}/v3/enrollment/create/phrAddress",
            json={"txnId": "abha-creation-txn-id", "preferredPhrAddress": "john123@abdm"},
            headers={"X-token": "enrollment-token"},
        )
        card_response = await client.get(
            f"{settings.API_V1_STR}/v3/profile/account/abha-card",
            headers={"X-token": "profile-token"},
        )

    assert [suggestions_response.status_code, create_response.status_code, card_response.status_code] == [200, 200, 200]
    assert [call["path"] for call in stub.calls] == [
        settings.ABDM_ABHA_V3_ADDRESS_SUGGESTIONS_PATH,
        settings.ABDM_ABHA_V3_CREATE_PHR_ADDRESS_PATH,
        settings.ABDM_ABHA_V3_ABHA_CARD_PATH,
    ]
    assert stub.calls[0]["body"] == {"txnId": "abha-creation-txn-id"}
    assert stub.calls[1]["body"] == {"txnId": "abha-creation-txn-id", "preferredPhrAddress": "john123@abdm"}
    assert stub.calls[2]["body"] is None
    assert stub.calls[0]["extra_headers"]["X-token"] == "enrollment-token"
    assert stub.calls[2]["extra_headers"]["X-token"] == "profile-token"


@pytest.mark.asyncio
async def test_abha_v3_account_mobile_update_request_otp_forwards_payload() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {
        "scope": ["abha-profile", "mobile-verify"],
        "loginHint": "mobile",
        "loginId": "ENCRYPTED_MOBILE",
        "otpSystem": "abdm",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/profile/account/request/otp",
            json=payload,
            headers={"X-token": "profile-token"},
        )

    assert response.status_code == 200
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_ACCOUNT_REQUEST_OTP_PATH
    assert stub.calls[0]["extra_headers"]["X-token"] == "profile-token"
    assert stub.calls[0]["body"] == payload


@pytest.mark.asyncio
async def test_abha_v3_account_request_otp_encrypts_plain_mobile() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/profile/account/request/otp",
                json={
                    "scope": ["abha-profile", "mobile-verify"],
                    "loginHint": "mobile",
                    "loginId": "+919876543210",
                    "otpSystem": "abdm",
                },
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp

    assert response.status_code == 200
    assert len(stub.calls) == 2
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_ACCOUNT_REQUEST_OTP_PATH
    assert stub.calls[1]["body"]["loginId"] == "encrypted-9876543210"


@pytest.mark.asyncio
async def test_abha_v3_account_verify_forwards_payload() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    payload = {
        "scope": ["abha-profile", "mobile-verify"],
        "authData": {
            "authMethods": ["otp"],
            "otp": {"txnId": "account-otp-txn-id", "otpValue": "ENCRYPTED_OTP"},
        },
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/abha/v3/profile/account/verify",
            json=payload,
            headers={"X-token": "profile-token"},
        )

    assert response.status_code == 200
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_ACCOUNT_VERIFY_PATH
    assert stub.calls[0]["extra_headers"]["X-token"] == "profile-token"
    assert stub.calls[0]["body"] == payload


@pytest.mark.asyncio
async def test_abha_v3_account_verify_encrypts_plain_otp() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/profile/account/verify",
                json={
                    "scope": ["abha-profile", "mobile-verify"],
                    "authData": {
                        "authMethods": ["otp"],
                        "otp": {"txnId": "account-otp-txn-id", "otpValue": "123456"},
                    },
                },
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp

    assert response.status_code == 200
    assert len(stub.calls) == 2
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_ACCOUNT_VERIFY_PATH
    assert stub.calls[1]["body"]["authData"]["otp"]["otpValue"] == "encrypted-123456"


@pytest.mark.asyncio
async def test_abha_registration_mobile_otp_flow_forwards_payloads() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            generate_response = await client.post(
                f"{settings.API_V1_STR}/registration/aadhaar/generateMobileOTP",
                json={"mobile": "9876543210", "txnId": "aadhaar-verification-txn-id"},
            )
            verify_response = await client.post(
                f"{settings.API_V1_STR}/registration/aadhaar/verifyMobileOTP",
                json={"otp": "123456", "txnId": "mobile-otp-txn-id"},
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp

    assert generate_response.status_code == 200
    assert verify_response.status_code == 200
    assert [call["path"] for call in stub.calls] == [
        settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH,
        settings.ABDM_ABHA_GENERATE_MOBILE_OTP_PATH,
        settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH,
        settings.ABDM_ABHA_VERIFY_MOBILE_OTP_PATH,
    ]
    assert stub.calls[1]["body"] == {"mobile": "encrypted-9876543210", "txnId": "aadhaar-verification-txn-id"}
    assert stub.calls[3]["body"] == {"otp": "encrypted-123456", "txnId": "mobile-otp-txn-id"}


@pytest.mark.asyncio
async def test_abha_aadhaar_preverified_registration_forwards_payloads() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    create_payload = {
        "txnId": "verified-mobile-txn-id",
        "firstName": "Rahul",
        "lastName": "Sharma",
        "gender": "M",
        "dayOfBirth": "10",
        "monthOfBirth": "10",
        "yearOfBirth": "1994",
        "stateCode": "29",
        "districtCode": "536",
        "healthId": "rahul.sharma@sbx",
    }

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            verify_response = await client.post(
                f"{settings.API_V1_STR}/registration/aadhaar/verifyOTP",
                json={"otp": "123456", "txnId": "aadhaar-otp-txn-id", "mobile": "+919876543210"},
            )
            create_response = await client.post(
                f"{settings.API_V1_STR}/registration/aadhaar/createHealthIdWithPreVerified",
                json=create_payload,
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp

    assert verify_response.status_code == 200
    assert create_response.status_code == 200
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_ENROLL_BY_AADHAAR_PATH
    assert stub.calls[1]["base_url"] == settings.ABDM_ABHA_V3_BASE_URL
    assert stub.calls[1]["body"] == {
        "authData": {
            "authMethods": ["otp"],
            "otp": {
                "txnId": "aadhaar-otp-txn-id",
                "otpValue": "encrypted-123456",
                "mobile": "9876543210",
            },
        },
        "consent": {"code": "abha-enrollment", "version": "1.4"},
    }
    assert stub.calls[2]["path"] == settings.ABDM_ABHA_CREATE_ADDRESS_PATH
    assert stub.calls[2]["body"] == create_payload


@pytest.mark.asyncio
async def test_legacy_aadhaar_generate_otp_alias_uses_v3_and_encrypts_plain_aadhaar() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.post(
                f"{settings.API_V1_STR}/registration/aadhaar/generateOtp",
                json={"aadhaar": "464565973146"},
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt

    assert response.status_code == 200
    assert len(stub.calls) == 2
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH
    assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_ENROLL_REQUEST_OTP_PATH
    assert stub.calls[1]["base_url"] == settings.ABDM_ABHA_V3_BASE_URL
    assert stub.calls[1]["body"] == {
        "txnId": "",
        "scope": ["abha-enrol"],
        "loginHint": "aadhaar",
        "loginId": "encrypted-464565973146",
        "otpSystem": "aadhaar",
    }


@pytest.mark.asyncio
async def test_abha_change_mobile_flow_forwards_payloads() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    original_encrypt = abdm_routes.encrypt_abha_value
    original_encrypt_otp = abdm_routes.encrypt_otp
    abdm_routes.encrypt_abha_value = lambda value, public_key: f"encrypted-{value}"
    abdm_routes.encrypt_otp = lambda value, public_key: f"encrypted-{value}"
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            await client.post(
                f"{settings.API_V1_STR}/account/change/mobile/new/generateOTP",
                json={"mobile": "9876543210"},
            )
            await client.post(
                f"{settings.API_V1_STR}/account/change/mobile/new/verifyOTP",
                json={"otp": "123456", "txnId": "new-mobile-txn-id"},
            )
            await client.post(
                f"{settings.API_V1_STR}/account/change/mobile/aadhaar/generateOTP",
                json={"txnId": "verified-mobile-txn-id"},
            )
            await client.post(
                f"{settings.API_V1_STR}/account/change/mobile/update/authentication",
                json={"otp": "654321", "txnId": "aadhaar-auth-txn-id"},
            )
    finally:
        abdm_routes.encrypt_abha_value = original_encrypt
        abdm_routes.encrypt_otp = original_encrypt_otp

    assert [call["path"] for call in stub.calls] == [
        settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH,
        settings.ABDM_ABHA_CHANGE_MOBILE_NEW_GENERATE_OTP_PATH,
        settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH,
        settings.ABDM_ABHA_CHANGE_MOBILE_NEW_VERIFY_OTP_PATH,
        settings.ABDM_ABHA_CHANGE_MOBILE_AADHAAR_GENERATE_OTP_PATH,
        settings.ABDM_ABHA_V3_PUBLIC_CERT_PATH,
        settings.ABDM_ABHA_CHANGE_MOBILE_UPDATE_AUTH_PATH,
    ]
    assert [call["body"] for call in stub.calls] == [
        None,
        {"mobile": "encrypted-9876543210"},
        None,
        {"otp": "encrypted-123456", "txnId": "new-mobile-txn-id"},
        {"txnId": "verified-mobile-txn-id"},
        None,
        {"otp": "encrypted-654321", "txnId": "aadhaar-auth-txn-id"},
    ]


@pytest.mark.asyncio
async def test_abha_change_mobile_old_mobile_otp_forwards_payload() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/account/change/mobile/old/generateOTP",
            json={"txnId": "verified-mobile-txn-id"},
        )

    assert response.status_code == 200
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_CHANGE_MOBILE_OLD_GENERATE_OTP_PATH
    assert stub.calls[0]["body"] == {"txnId": "verified-mobile-txn-id"}


@pytest.mark.asyncio
async def test_abha_v3_address_suggestions_by_txn_uses_cached_enrollment_token() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient(
        get_responses=[{"phrAddress": ["dhruva@abdm", "dhruva123@abdm"]}],
    )
    app = create_app()
    txn_id = "2ec82835-9314-4296-acc0-5d526371998d"
    abdm_routes.ABHA_ENROLLMENT_TOKENS[txn_id] = {"token": "enrollment-access-token", "stored_at": 0}

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.get(f"{settings.API_V1_STR}/abha/v3/address/suggestions/{txn_id}")

        assert response.status_code == 200
        assert response.json() == {"phrAddress": ["dhruva@abdm", "dhruva123@abdm"]}
        assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_ENROL_SUGGESTIONS_GET_PATH
        assert stub.calls[0]["body"] is None
        assert stub.calls[0]["extra_headers"]["X-Token"] == "enrollment-access-token"
    finally:
        abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()


@pytest.mark.asyncio
async def test_abha_v3_address_create_validates_and_caches_address() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient(
        post_responses=[{"phrAddress": "dhruva@abdm", "status": "ACTIVE"}],
    )
    app = create_app()
    txn_id = "2ec82835-9314-4296-acc0-5d526371998d"
    abdm_routes.ABHA_ENROLLMENT_TOKENS[txn_id] = {"token": "enrollment-access-token", "stored_at": 0}
    abdm_routes.ABHA_ADDRESS_CACHE.clear()

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            invalid = await client.post(
                f"{settings.API_V1_STR}/abha/v3/address/create",
                json={"txnId": txn_id, "phrAddress": "ab"},
            )
            invalid_suffix = await client.post(
                f"{settings.API_V1_STR}/abha/v3/address/create",
                json={"txnId": txn_id, "phrAddress": "dhruva@bad"},
            )
            valid = await client.post(
                f"{settings.API_V1_STR}/abha/v3/address/create",
                json={"txnId": txn_id, "phrAddress": "dhruva@abdm"},
            )

        assert invalid.status_code == 422
        assert invalid_suffix.status_code == 422
        assert valid.status_code == 200
        assert valid.json() == {"phrAddress": "dhruva@abdm", "status": "ACTIVE"}
        assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_ENROL_ADDRESS_PATH
        assert stub.calls[0]["body"] == {"txnId": txn_id, "abhaAddress": "dhruva@abdm"}
        assert stub.calls[0]["extra_headers"]["X-Token"] == "enrollment-access-token"
        assert abdm_routes.ABHA_ADDRESS_CACHE[txn_id] == "dhruva@abdm"
    finally:
        abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()
        abdm_routes.ABHA_ADDRESS_CACHE.clear()


@pytest.mark.asyncio
async def test_abha_v3_card_by_txn_wraps_base64_response() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient(
        get_responses=[{"card": "Base64EncodedPDFOrImage"}],
    )
    app = create_app()
    txn_id = "2ec82835-9314-4296-acc0-5d526371998d"
    abdm_routes.ABHA_ENROLLMENT_TOKENS[txn_id] = {"token": "enrollment-access-token", "stored_at": 0}

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            response = await client.get(f"{settings.API_V1_STR}/abha/v3/card/{txn_id}")

        assert response.status_code == 200
        assert response.json() == {"success": True, "card": "Base64EncodedPDFOrImage"}
        assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_ACCOUNT_CARD_PATH
        assert stub.calls[0]["extra_headers"]["X-Token"] == "enrollment-access-token"
    finally:
        abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()


@pytest.mark.asyncio
async def test_abha_v3_card_by_txn_uses_top_level_enrollment_token() -> None:
    _configure_test_settings()
    app = create_app()
    txn_id = "original-otp-txn-id"
    stub = StubABDMGatewayClient(
        post_responses=[{"txnId": txn_id, "token": "enrollment-access-token"}],
        get_responses=[{"card": "Base64EncodedPDFOrImage"}],
    )

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            set_abdm_gateway_client(stub)
            verify_response = await client.post(
                f"{settings.API_V1_STR}/abha/v3/enrollment/enrol/byAadhaar",
                json={
                    "authData": {
                        "authMethods": ["otp"],
                        "otp": {
                            "txnId": txn_id,
                            "otpValue": "encrypted-otp",
                            "mobile": "9876543210",
                        },
                    }
                },
            )
            card_response = await client.get(f"{settings.API_V1_STR}/abha/v3/card/{txn_id}")

        assert verify_response.status_code == 200
        assert card_response.status_code == 200
        assert card_response.json() == {"success": True, "card": "Base64EncodedPDFOrImage"}
        assert stub.calls[1]["path"] == settings.ABDM_ABHA_V3_ACCOUNT_CARD_PATH
        assert stub.calls[1]["extra_headers"]["X-Token"] == "enrollment-access-token"
    finally:
        abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()


@pytest.mark.asyncio
async def test_abha_v3_address_suggestions_requires_enrollment_token() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()
    abdm_routes.ABHA_ENROLLMENT_TOKENS.clear()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.get(
            f"{settings.API_V1_STR}/abha/v3/address/suggestions/missing-txn-id",
        )

    assert response.status_code == 401
    assert stub.calls == []


@pytest.mark.asyncio
async def test_abha_v3_profile_account_abha_card_download() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient(
        get_responses=[{"card": "Base64OrPDFContent"}],
    )
    app = create_app()

    headers = {
        "X-token": "test-user-jwt-token",
        "REQUEST-ID": "18235d89-cb13-479d-ad71-7a57d5f669a8",
        "TIMESTAMP": "2026-08-04T05:45:20.123Z",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        res1 = await client.get(
            f"{settings.API_V1_STR}/abha/v3/profile/account/abha-card",
            headers=headers,
        )
        res2 = await client.get(
            f"{settings.API_V1_STR}/v3/profile/account/abha-card",
            headers=headers,
        )

    assert res1.status_code == 200
    assert res2.status_code == 200
    assert stub.calls[0]["path"] == settings.ABDM_ABHA_V3_ABHA_CARD_PATH
    assert stub.calls[0]["extra_headers"]["X-token"] == "test-user-jwt-token"
    assert stub.calls[0]["extra_headers"]["REQUEST-ID"] == "18235d89-cb13-479d-ad71-7a57d5f669a8"


@pytest.mark.asyncio
async def test_abha_v3_get_profile_and_qr_code() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient(
        get_responses=[
            {"name": "Rahul Kumar Sharma", "ABHANumber": "91-1783-8610-1251"},
            {"qrCode": "data:image/png;base64,TEST_QR"},
        ],
    )
    app = create_app()

    headers = {"X-token": "test-jwt-token"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        prof_res = await client.get(
            f"{settings.API_V1_STR}/v3/profile/account",
            headers=headers,
        )
        qr_res = await client.get(
            f"{settings.API_V1_STR}/v3/profile/account/qrCode",
            headers=headers,
        )

    assert prof_res.status_code == 200
    assert qr_res.status_code == 200
    assert prof_res.json()["name"] == "Rahul Kumar Sharma"
    assert qr_res.json()["qrCode"] == "data:image/png;base64,TEST_QR"


@pytest.mark.asyncio
async def test_admin_transactions_and_api_logs() -> None:
    _configure_test_settings()
    app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        txns_res = await client.get(f"{settings.API_V1_STR}/admin/transactions")
        logs_res = await client.get(f"{settings.API_V1_STR}/admin/api-logs")

    assert txns_res.status_code == 200
    assert logs_res.status_code == 200
    assert "count" in txns_res.json()
    assert "count" in logs_res.json()


