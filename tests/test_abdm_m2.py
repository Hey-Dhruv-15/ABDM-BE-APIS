import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes import abdm as abdm_routes
from app.api.dependencies import set_abdm_auth_service, set_abdm_gateway_client
from app.main import create_app
from app.orchestration.abha_state import abha_workflow_store
from app.settings import settings
from app.abdm.json_storage import reset_json_storage


class StubABDMAuthService:
    async def get_token(self, force_refresh: bool = False) -> str:
        return "test-token"

    def token_expiry(self) -> datetime | None:
        return datetime.now(timezone.utc) + timedelta(hours=1)


class StubABDMGatewayClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def get(
        self,
        path: str,
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
                "method": "GET",
                "path": path,
                "body": None,
                "include_participant_header": include_participant_header,
                "participant_id": participant_id,
                "participant_type": participant_type,
                "base_url": base_url,
                "extra_headers": extra_headers or {},
                "include_cm_header": include_cm_header,
                "include_auth_header": include_auth_header,
            }
        )
        if path == settings.ABDM_M2_OPENID_CONFIG_PATH:
            return {"jwks_uri": "https://dev.abdm.gov.in/api/hiecm/gateway/v3/certs"}
        if path == settings.ABDM_M2_CERTS_PATH:
            return {"keys": [{"kid": "key-id", "kty": "RSA", "alg": "RS256", "use": "sig", "x5c": ["certificate"]}]}
        if path == settings.ABDM_M2_BRIDGE_SERVICES_PATH:
            return {"bridge": {"id": "SBX_XXXX"}, "services": []}
        return {"id": 1561, "serviceId": "TestClinicHIP"}

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
                "method": "POST",
                "path": path,
                "body": body,
                "include_participant_header": include_participant_header,
                "participant_id": participant_id,
                "participant_type": participant_type,
                "base_url": base_url,
                "extra_headers": extra_headers or {},
                "include_cm_header": include_cm_header,
                "include_auth_header": include_auth_header,
            }
        )
        return {"status": "Accepted"}

    async def patch(
        self,
        path: str,
        body: dict | None = None,
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
                "method": "PATCH",
                "path": path,
                "body": body,
                "include_participant_header": include_participant_header,
                "participant_id": participant_id,
                "participant_type": participant_type,
                "base_url": base_url,
                "extra_headers": extra_headers or {},
                "include_cm_header": include_cm_header,
                "include_auth_header": include_auth_header,
            }
        )
        return {"status": "Accepted"}

    async def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
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
                "method": method,
                "path": path,
                "body": body,
                "include_participant_header": include_participant_header,
                "participant_id": participant_id,
                "participant_type": participant_type,
                "base_url": base_url,
                "extra_headers": extra_headers or {},
                "include_cm_header": include_cm_header,
                "include_auth_header": include_auth_header,
            }
        )
        return {"status": "Accepted"}


def _configure_test_settings() -> None:
    settings.ENFORCE_REGION_HEADER = False
    settings.REQUIRE_AUTHORIZATION_HEADER = False
    settings.REQUIRE_JWT_VALIDATION = False
    settings.ENABLE_ABHA = True
    settings.REGION = "india"
    settings.ABDM_CM_ID = "sbx"
    settings.ABDM_INTEGRATION_ID = "test-relay"
    settings.ENABLED_NETWORKS = "ABHA"
    settings.REGION_NETWORK_MAP = "india:ABHA"
    settings.ABDM_LINKAGE_MONGO_ENABLED = False
    settings.ABDM_HIP_ID = "IN2810014366"
    settings.ABDM_BRIDGE_URL = ""
    settings.GATEWAY_DEFAULT_DATA_PUSH_URL = ""
    settings.ABDM_M2_OPENID_CONFIG_PATH = "/api/hiecm/gateway/v3/.well-known/openid-configuration"
    settings.ABDM_M2_CERTS_PATH = "/api/hiecm/gateway/v3/certs"
    settings.ABDM_M2_BRIDGE_URL_PATH = "/api/hiecm/gateway/v3/bridge/url"
    settings.ABDM_M2_BRIDGE_SERVICE_BY_ID_PATH = "/api/hiecm/gateway/v3/bridge-service/serviceId/{serviceId}"
    settings.ABDM_M2_BRIDGE_SERVICES_PATH = "/api/hiecm/gateway/v3/bridge-services"
    settings.ABDM_M2_BRIDGE_SERVICES_UPDATE_PATH = "/v4/int/v1/bridges/MutipleHRPAddUpdateServices"
    settings.ABDM_M2_LINK_TOKEN_GENERATE_PATH = "/api/hiecm/v3/token/generate-token"
    settings.ABDM_M2_LINK_CARE_CONTEXT_PATH = "/api/hiecm/hip/v3/link/carecontext"


def _reset_workflow_store() -> None:
    reset_json_storage()
    abha_workflow_store._by_correlation.clear()
    abha_workflow_store._request_to_correlation.clear()
    abha_workflow_store._consent_to_correlation.clear()
    abha_workflow_store._transaction_to_correlation.clear()
    abha_workflow_store._abha_to_correlation.clear()


def _m2_headers() -> dict[str, str]:
    return {
        "REQUEST-ID": "req-123",
        "TIMESTAMP": "2022-10-06T10:10:00.587Z",
        "X-CM-ID": "Sbx",
        "X-Region": "india",
        "X-Integration": "test-relay",
    }


def _unsigned_jwt(claims: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}

    def encode(segment: dict) -> str:
        raw = json.dumps(segment, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encode(header)}.{encode(claims)}."





@pytest.mark.asyncio
async def test_m2_sessions_endpoint_does_not_require_bearer_token() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    endpoints = [
        f"{settings.API_V1_STR}/abdm/m1/sessions?force_refresh=false",
        f"{settings.API_V1_STR}/hiecm/gateway/v3/sessions?force_refresh=false",
        f"{settings.API_V1_STR}/abdm/m3/sessions?force_refresh=false",
        f"{settings.API_V1_STR}/sessions?force_refresh=false",
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_auth_service(StubABDMAuthService())
        set_abdm_gateway_client(stub)
        for endpoint in endpoints:
            response = await client.post(
                endpoint,
                headers=_m2_headers(),
            )
            assert response.status_code == 200, f"Failed for endpoint {endpoint}: {response.text}"
            assert response.json()["tokenType"] == "Bearer"



@pytest.mark.asyncio
async def test_m2_bridge_management_endpoints_use_configured_paths() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()
    headers = {**_m2_headers(), "Authorization": "Bearer test-token"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        bridge_url = await client.patch(
            f"{settings.API_V1_STR}/hiecm/gateway/v3/bridge/url",
            json={"url": "https://webhook.site/example"},
            headers=headers,
        )
        linkage = await client.post(
            f"{settings.API_V1_STR}/v1/bridges/MutipleHRPAddUpdateServices",
            json={
                "facilityId": "IN02100000XX",
                "facilityName": "XYZ Hospital",
                "bridgeId": "SBX_XXXXX",
                "hipName": "XYZ BRIDGE",
                "type": "HIP",
                "active": True,
            },
            headers=headers,
        )
        service = await client.get(
            f"{settings.API_V1_STR}/hiecm/gateway/v3/bridge-service/serviceId/TestClinicHIP",
            headers=headers,
        )
        services = await client.get(f"{settings.API_V1_STR}/hiecm/gateway/v3/bridge-services", headers=headers)

    assert [bridge_url.status_code, linkage.status_code, service.status_code, services.status_code] == [200, 200, 200, 200]
    assert [call["method"] for call in stub.calls] == ["PATCH", "POST", "GET", "GET"]
    assert [call["path"] for call in stub.calls] == [
        settings.ABDM_M2_BRIDGE_URL_PATH,
        settings.ABDM_M2_BRIDGE_SERVICES_UPDATE_PATH,
        "/api/hiecm/gateway/v3/bridge-service/serviceId/TestClinicHIP",
        settings.ABDM_M2_BRIDGE_SERVICES_PATH,
    ]
    assert all(call["extra_headers"] == _m2_headers() for call in stub.calls)


@pytest.mark.asyncio
async def test_m2_link_token_accepts_numeric_abha_number_and_uses_hip_header() -> None:
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()
    headers = {**_m2_headers(), "Authorization": "Bearer test-token", "X-HIP-ID": "IN2810014366"}
    payload = {
        "abhaNumber": 98765432101234,
        "abhaAddress": "user@sbx",
        "name": "Arjun",
        "gender": "M",
        "yearOfBirth": 1998,
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/hiecm/v3/token/generate-token",
            json=payload,
            headers=headers,
        )

    assert response.status_code == 200
    call = stub.calls[0]
    assert call["path"] == settings.ABDM_M2_LINK_TOKEN_GENERATE_PATH
    assert call["body"] == payload
    assert call["participant_type"] == "HIP"
    assert call["participant_id"] == "IN2810014366"
    assert call["extra_headers"]["X-HIP-ID"] == "IN2810014366"


@pytest.mark.asyncio
async def test_m2_link_care_context_moves_body_link_token_to_header_and_forwards_headers() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    stub = StubABDMGatewayClient()
    app = create_app()
    abha_address = "91687401063254@sbx"
    link_token = _unsigned_jwt({"hipId": "Hip_11", "abhaAddress": abha_address})
    payload = {
        "abhaNumber": "91687401063254",
        "abhaAddress": abha_address,
        "patient": [
            {
                "referenceNumber": "REF001",
                "display": "Visit 1",
                "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                "hiType": "Prescription",
                "count": 1,
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json=payload,
            headers={
                "Authorization": "Bearer access-token",
                "REQUEST-ID": "18235d89-cb13-479d-ad71-7a57d5f669a8",
                "TIMESTAMP": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
                "X-LINK-TOKEN": link_token,
            },
        )

    assert response.status_code == 202
    call = stub.calls[0]
    assert call["path"] == settings.ABDM_M2_LINK_CARE_CONTEXT_PATH
    assert call["body"] == {
        "abhaNumber": payload["abhaNumber"],
        "abhaAddress": payload["abhaAddress"],
        "patient": payload["patient"],
    }
    assert "linkToken" not in call["body"]
    assert call["participant_id"] == "Hip_11"
    assert call["extra_headers"]["REQUEST-ID"] == "18235d89-cb13-479d-ad71-7a57d5f669a8"
    assert call["extra_headers"]["X-LINK-TOKEN"] == link_token


@pytest.mark.asyncio
async def test_m2_link_care_context_requires_link_token_header() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    app = create_app()
    payload = {
        "abhaNumber": "91687401063254",
        "abhaAddress": "91687401063254@sbx",
        "patient": [
            {
                "referenceNumber": "REF001",
                "display": "Visit 1",
                "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                "hiType": "Prescription",
                "count": 1,
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json=payload,
            headers={
                "Authorization": "Bearer access-token",
                "REQUEST-ID": "18235d89-cb13-479d-ad71-7a57d5f669a8",
                "TIMESTAMP": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "X-LINK-TOKEN header missing"


@pytest.mark.asyncio
async def test_m2_link_care_context_auto_fetches_from_storage() -> None:
    from app.api.routes.abdm import update_entry
    _reset_workflow_store()
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()
    abha_address = "91687401063254@sbx"
    link_token = _unsigned_jwt({"hipId": "Hip_11", "abhaAddress": abha_address})

    # Pre-cache/store the link token in local storage
    update_entry("link_tokens", abha_address, {"linkToken": link_token})

    payload = {
        "abhaNumber": "91687401063254",
        "abhaAddress": abha_address,
        "patient": [
            {
                "referenceNumber": "REF001",
                "display": "Visit 1",
                "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                "hiType": "Prescription",
                "count": 1,
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json=payload,
            headers={
                "Authorization": "Bearer access-token",
                "REQUEST-ID": "18235d89-cb13-479d-ad71-7a57d5f669a8",
                "TIMESTAMP": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
            },
        )

    assert response.status_code == 202
    call = stub.calls[0]
    assert call["extra_headers"]["X-LINK-TOKEN"] == link_token


@pytest.mark.asyncio
async def test_m2_link_care_context_auto_generates_request_metadata() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    stub = StubABDMGatewayClient()
    app = create_app()
    abha_address = "91687401063254@sbx"
    link_token = _unsigned_jwt({"hipId": "Hip_11", "abhaAddress": abha_address})
    payload = {
        "abhaNumber": "91687401063254",
        "abhaAddress": abha_address,
        "patient": [
            {
                "referenceNumber": "REF001",
                "display": "Visit 1",
                "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                "hiType": "Prescription",
                "count": 1,
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json=payload,
            headers={
                "Authorization": "Bearer access-token",
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
                "X-LINK-TOKEN": link_token,
            },
        )

    assert response.status_code == 202
    forwarded_headers = stub.calls[0]["extra_headers"]
    UUID(forwarded_headers["REQUEST-ID"])
    assert forwarded_headers["TIMESTAMP"].endswith("Z")
    assert forwarded_headers["X-LINK-TOKEN"] == link_token


@pytest.mark.asyncio
async def test_m2_care_contexts_discover_returns_linked_contexts() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    stub = StubABDMGatewayClient()
    app = create_app()
    abha_address = "91687401063254@sbx"
    link_token = _unsigned_jwt({"hipId": "Hip_11", "abhaAddress": abha_address})
    linked_payload = {
        "abhaNumber": "91687401063254",
        "abhaAddress": abha_address,
        "patient": [
            {
                "referenceNumber": "REF001",
                "display": "Visit 1",
                "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                "hiType": "Prescription",
                "count": 1,
            }
        ],
    }
    discover_payload = {
        "transactionId": "550e8400-e29b-41d4-a716-446655440000",
        "patient": {"id": abha_address},
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        link_response = await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json=linked_payload,
            headers={
                "Authorization": "Bearer access-token",
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
                "X-LINK-TOKEN": link_token,
            },
        )
        discover_response = await client.post(
            f"{settings.API_V1_STR}/care-contexts/discover",
            json=discover_payload,
            headers={
                "Authorization": "Bearer access-token",
                "X-CM-ID": "sbx",
                "X-Region": "india",
                "X-Integration": "test-relay",
            },
        )

    assert link_response.status_code == 202
    assert discover_response.status_code == 200
    res_data = discover_response.json()
    assert res_data["transactionId"] == discover_payload["transactionId"]
    assert res_data["matchedBy"] == ["ABHA_ADDRESS"]
    assert res_data["response"]["requestId"] == discover_payload["transactionId"]
    assert len(res_data["patient"]) == 1
    assert res_data["patient"][0]["referenceNumber"] == "REF001"
    assert res_data["patient"][0]["careContexts"][0]["referenceNumber"] == "CC001"


@pytest.mark.asyncio
async def test_m2_get_patient_links_returns_linked_records() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    settings.ABDM_HIP_ID = "Hip_11"
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    stub = StubABDMGatewayClient()
    app = create_app()
    abha_address = "91687401063254@sbx"
    link_token = _unsigned_jwt({"hipId": "Hip_11", "abhaAddress": abha_address})
    linked_payload = {
        "abhaNumber": "91687401063254",
        "abhaAddress": abha_address,
        "patient": [
            {
                "referenceNumber": "REF001",
                "display": "Visit 1",
                "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                "hiType": "Prescription",
                "count": 1,
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json=linked_payload,
            headers={
                "Authorization": "Bearer access-token",
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
                "X-LINK-TOKEN": link_token,
            },
        )
        response = await client.get(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links",
            headers={
                "Authorization": "Bearer access-token",
                "X-AUTH-TOKEN": "opaque-abdm-auth-token",
                "X-CM-ID": "sbx",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["patient"]["id"] == abha_address
    assert body["patient"]["links"][0]["hip"] == {"id": "Hip_11", "name": "Hip_11", "type": "HIP"}
    assert body["patient"]["links"][0]["referenceNumber"] == "REF001"
    assert body["patient"]["links"][0]["careContexts"] == [{"referenceNumber": "CC001", "display": "Prescription"}]


@pytest.mark.asyncio
async def test_m2_context_notify_sms_and_callback_accept_linked_contexts() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    settings.ABDM_HIP_ID = "Hip_11"
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    stub = StubABDMGatewayClient()
    app = create_app()
    abha_address = "91687401063254@sbx"
    link_token = _unsigned_jwt({"hipId": "Hip_11", "abhaAddress": abha_address})
    linked_payload = {
        "abhaNumber": "91687401063254",
        "abhaAddress": abha_address,
        "patient": [
            {
                "referenceNumber": "REF001",
                "display": "Visit 1",
                "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                "hiType": "Prescription",
                "count": 1,
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json=linked_payload,
            headers={
                "Authorization": "Bearer access-token",
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
                "X-LINK-TOKEN": link_token,
            },
        )
        notify_response = await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/context/notify",
            json={
                "notification": {
                    "patient": {"id": abha_address},
                    "careContext": {"patientReference": "REF001", "careContextReference": "CC001"},
                    "hiTypes": ["OPConsultation"],
                    "date": "2026-05-19T09:35:00.000Z",
                    "hip": {"id": "Hip_11"},
                }
            },
            headers={
                "Authorization": "Bearer access-token",
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
            },
        )
        callback_response = await client.post(
            f"{settings.API_V1_STR}/v3/links/context/on-notify",
            json={
                "requestId": "743ec386-670f-43a8-a3ed-44aa30fb15fb",
                "timestamp": "2026-05-19T09:40:00.000Z",
                "acknowledgement": {"status": "SUCCESS"},
                "response": {"requestId": "6f0b4665-a915-4c92-aa36-65afb4a2cd71"},
            },
            headers={"X-CM-ID": "sbx"},
        )
        sms_response = await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/patient/links/sms/notify2",
            json={
                "notification": {
                    "phoneNo": "9876543210",
                    "hip": {"id": "Hip_11", "name": "ABC Hospital"},
                }
            },
            headers={
                "Authorization": "Bearer access-token",
                "X-CM-ID": "sbx",
            },
        )

    assert notify_response.status_code == 202
    assert notify_response.json() == {"acknowledgement": {"status": "OK"}}
    assert callback_response.status_code == 202
    assert callback_response.json() == {"acknowledgement": {"status": "OK"}}
    assert sms_response.status_code == 202
    assert not sms_response.content


@pytest.mark.asyncio
async def test_m2_consent_notification_validates_links_and_persists(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset_workflow_store()
    _configure_test_settings()
    settings.ABDM_HIP_ID = "Hip_11"
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    stub = StubABDMGatewayClient()
    app = create_app()
    abha_address = "91687401063254@sbx"
    captured: dict = {}

    async def fake_upsert_consent(**kwargs: dict) -> dict:
        captured.update(kwargs)
        return kwargs

    monkeypatch.setattr(abdm_routes.consent_repository, "upsert_consent", fake_upsert_consent)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json={
                "abhaNumber": "91687401063254",
                "abhaAddress": abha_address,
                "patient": [
                    {
                        "referenceNumber": "REF001",
                        "display": "Visit 1",
                        "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                        "hiType": "Prescription",
                        "count": 1,
                    }
                ],
            },
            headers={
                "Authorization": "Bearer access-token",
                "X-CM-ID": "sbx",
                "X-HIP-ID": "Hip_11",
                "X-LINK-TOKEN": _unsigned_jwt({"hipId": "Hip_11", "abhaAddress": abha_address}),
            },
        )
        response = await client.post(
            f"{settings.API_V1_STR}/consent/notification",
            json={
                "consentId": "consent-123",
                "notification": {
                    "status": "GRANTED",
                    "transactionId": "txn-123",
                    "patient": {"id": abha_address},
                    "hip": {"id": "Hip_11"},
                    "hiu": {"id": "HIU_11"},
                    "careContexts": [{"patientReference": "REF001", "careContextReference": "CC001"}],
                    "purpose": {"text": "Treatment"},
                    "permission": {
                        "accessMode": "VIEW",
                        "dateRange": {
                            "from": "2026-05-19T09:00:00.000Z",
                            "to": "2026-05-20T09:00:00.000Z",
                        },
                        "dataEraseAt": "2026-06-19T09:00:00.000Z",
                    },
                },
            },
            headers={"X-CM-ID": "sbx"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["acknowledgement"]["status"] == "OK"
    assert body["transactionId"] == "txn-123"
    assert body["consentIds"] == ["consent-123"]
    assert body["receivedEntries"] == 1
    UUID(body["requestId"])
    assert captured["consent_id"] == "consent-123"
    assert captured["payload"]["notification"]["status"] == "GRANTED"


@pytest.mark.asyncio
async def test_m2_link_care_context_rejects_link_token_in_body() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    app = create_app()
    payload = {
        "abhaNumber": "91687401063254",
        "abhaAddress": "91687401063254@sbx",
        "linkToken": "must-not-be-in-body",
        "patient": [
            {
                "referenceNumber": "REF001",
                "display": "Visit 1",
                "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                "hiType": "Prescription",
                "count": 1,
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext",
            json=payload,
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_m2_link_care_context_callback_requires_abdm_headers_and_schema() -> None:
    _configure_test_settings()
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    app = create_app()
    path = f"{settings.API_V1_STR}/v3/hip/link/on-care-context"
    link_token = _unsigned_jwt(
        {
            "hipId": "IN2810014366",
            "abhaNumber": "91178386101731",
            "abhaAddress": "abc@abdm",
        }
    )
    payload = {
        "abhaNumber": "91178386101731",
        "abhaAddress": "abc@abdm",
        "patient": [
            {
                "referenceNumber": "TMH-PUID-001",
                "display": "Display",
                "careContexts": [{"referenceNumber": "TMH-PUID-001", "display": "display 1"}],
                "hiType": "PRESCRIPTION",
                "count": 1,
            }
        ],
    }
    headers = {
        "Authorization": "Bearer access-token",
        "REQUEST-ID": "f29f0e59-8388-4698-9fe6-05db67aeac46",
        "TIMESTAMP": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "X-CM-ID": "sbx",
        "X-HIP-ID": "IN2810014366",
        "X-LINK-TOKEN": link_token,
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        missing_headers = await client.post(path, json=payload)
        bad_body = await client.post(path, json={"additionalProp1": {}}, headers=headers)
        response = await client.post(path, json=payload, headers=headers)

    assert missing_headers.status_code == 400
    assert missing_headers.json()["detail"] == "Missing ABDM headers: X-CM-ID"
    assert bad_body.status_code == 422
    assert response.status_code == 200
    assert response.json()["acknowledgement"]["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_m2_mandatory_certification_endpoints_routing() -> None:
    _configure_test_settings()
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    stub = StubABDMGatewayClient()
    app = create_app()

    headers = {
        "Authorization": "Bearer access-token",
        "REQUEST-ID": "18235d89-cb13-479d-ad71-7a57d5f669a8",
        "TIMESTAMP": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "X-CM-ID": "sbx",
        "X-HIP-ID": "IN2810014366",
        "X-LINK-TOKEN": _unsigned_jwt({"hipId": "IN2810014366", "abhaAddress": "abc@abdm"}),
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)

        # 1. Gateway & Setup
        res_sess = await client.post(f"{settings.API_V1_STR}/api/hiecm/gateway/v3/sessions", headers=headers)
        res_bridge = await client.patch(f"{settings.API_V1_STR}/api/hiecm/gateway/v3/bridge/url", json={"url": "https://bridge.local"}, headers=headers)

        # 2. HIP-Initiated Linking Flow
        res_gen = await client.post(f"{settings.API_V1_STR}/api/hiecm/v3/token/generate-token", json={"abhaNumber": "91178386101731", "abhaAddress": "abc@abdm", "name": "Test", "gender": "M", "yearOfBirth": 1990}, headers=headers)
        res_cb_gen = await client.post(f"{settings.API_V1_STR}/api/v3/hip/token/on-generate-token", json={"transactionId": "txn-1", "token": "token-1"}, headers=headers)
        res_link_cc = await client.post(f"{settings.API_V1_STR}/api/hiecm/hip/v3/link/carecontext", json={"abhaNumber": "91178386101731", "abhaAddress": "abc@abdm", "patient": [{"referenceNumber": "REF1", "display": "Visit 1", "careContexts": [{"referenceNumber": "CC1", "display": "Prescription"}], "hiType": "Prescription", "count": 1}]}, headers=headers)
        res_cb_link_cc = await client.post(f"{settings.API_V1_STR}/api/v3/link/on_carecontext", json={"abhaNumber": "91178386101731", "abhaAddress": "abc@abdm", "patient": [{"referenceNumber": "REF1", "display": "Visit 1", "careContexts": [{"referenceNumber": "CC1", "display": "Prescription"}], "hiType": "PRESCRIPTION", "count": 1}]}, headers=headers)

        # 3. User-Initiated Linking Flow
        res_disc_cb = await client.post(f"{settings.API_V1_STR}/v3/hip/patient/care-context/discover", json={"transactionId": "550e8400-e29b-41d4-a716-446655440000", "patient": {"id": "abc@abdm"}}, headers=headers)
        res_on_disc = await client.post(f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/patient/care-context/on-discover", json={"transactionId": "550e8400-e29b-41d4-a716-446655440000", "patient": [{"referenceNumber": "REF1", "display": "Visit 1", "careContexts": [{"referenceNumber": "CC1", "display": "Prescription"}], "hiType": "PRESCRIPTION", "count": 1}]}, headers=headers)
        res_init_cb = await client.post(f"{settings.API_V1_STR}/v3/hip/link/care-context/init", json={"transactionId": "550e8400-e29b-41d4-a716-446655440000"}, headers=headers)
        res_on_init = await client.post(f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/link/care-context/on-init", json={"transactionId": "550e8400-e29b-41d4-a716-446655440000", "link": {"referenceNumber": "REF1"}}, headers=headers)
        res_conf_cb = await client.post(f"{settings.API_V1_STR}/v3/hip/link/care-context/confirm", json={"confirmation": {"token": "123456", "linkRefNumber": "REF1"}}, headers=headers)
        res_on_conf = await client.post(f"{settings.API_V1_STR}/hiecm/user-initiated-linking/v3/link/care-context/on-confirm", json={"transactionId": "550e8400-e29b-41d4-a716-446655440000"}, headers=headers)

        # 4. Data Flow & Consent
        res_consent_cb = await client.post(f"{settings.API_V1_STR}/v3/consent/request/hip/notify", json={"consentId": "c1", "notification": {"status": "GRANTED", "transactionId": "txn1", "patient": {"id": "abc@abdm"}, "hip": {"id": "IN2810014366"}, "hiu": {"id": "HIU1"}, "careContexts": [], "purpose": {"text": "Treatment"}, "permission": {"accessMode": "VIEW", "dateRange": {"from": "2026-05-19T09:00:00.000Z", "to": "2026-05-20T09:00:00.000Z"}, "dataEraseAt": "2026-06-19T09:00:00.000Z"}}}, headers=headers)
        res_consent_on_not = await client.post(f"{settings.API_V1_STR}/hiecm/consent/v3/request/hip/on-notify", json={"acknowledgement": {"status": "OK"}}, headers=headers)
        res_hi_req = await client.post(f"{settings.API_V1_STR}/v3/hip/health-information/request", json={"consent": {"id": "c1"}, "dateRange": {"from": "2026-05-19T09:00:00.000Z", "to": "2026-05-20T09:00:00.000Z"}}, headers=headers)
        res_hi_on_req = await client.post(f"{settings.API_V1_STR}/hiecm/data-flow/v3/health-information/hip/on-request", json={"hiRequest": {"transactionId": "txn1", "sessionStatus": "ACKNOWLEDGED"}}, headers=headers)
        res_hi_notify = await client.post(f"{settings.API_V1_STR}/hiecm/data-flow/v3/health-information/notify", json={"notification": {"consentId": "c1", "transactionId": "txn1", "doneAt": "2026-05-19T09:00:00.000Z", "notifier": {"type": "HIP", "id": "IN2810014366"}, "statusNotification": {"sessionStatus": "TRANSFERRED", "hipId": "IN2810014366", "statusResponses": [{"careContextReference": "CC1", "hiStatus": "DELIVERED", "description": "FHIR data delivered successfully"}]}}}, headers=headers)

        # 5. Scan & Share
        res_on_share = await client.post(f"{settings.API_V1_STR}/hiecm/patient-share/v3/on-share", json={"acknowledgement": {"status": "SUCCESS"}}, headers=headers)

    assert res_sess.status_code == 200
    assert res_bridge.status_code == 200
    assert res_gen.status_code == 200
    assert res_cb_gen.status_code == 200
    assert res_link_cc.status_code == 202
    assert res_cb_link_cc.status_code == 200
    assert res_disc_cb.status_code == 200
    assert res_on_disc.status_code == 200
    assert res_init_cb.status_code == 200
    assert res_on_init.status_code == 200
    assert res_conf_cb.status_code == 200
    assert res_on_conf.status_code == 200
    assert res_consent_cb.status_code == 200
    assert res_consent_on_not.status_code == 200
    assert res_hi_req.status_code == 200
    assert res_hi_on_req.status_code == 200
    assert res_hi_notify.status_code == 200
    assert res_on_share.status_code == 200


@pytest.mark.asyncio
async def test_m2_link_care_context_callback_openapi_documents_required_headers_and_body() -> None:
    _configure_test_settings()
    app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"{settings.API_V1_STR}/openapi.json")

    assert response.status_code == 200
    operation = response.json()["paths"][f"{settings.API_V1_STR}/v3/hip/link/on-care-context"]["post"]
    parameters = {param["name"]: param for param in operation["parameters"]}
    assert parameters["REQUEST-ID"]["in"] == "header"
    assert parameters["REQUEST-ID"]["required"] is False
    assert parameters["TIMESTAMP"]["in"] == "header"
    assert parameters["TIMESTAMP"]["required"] is False
    assert parameters["X-HIP-ID"]["in"] == "header"
    assert parameters["X-HIP-ID"]["required"] is True
    assert parameters["X-CM-ID"]["in"] == "header"
    assert parameters["X-CM-ID"]["required"] is True
    assert parameters["X-LINK-TOKEN"]["in"] == "header"
    assert parameters["X-LINK-TOKEN"]["required"] is True
    assert parameters["Authorization"]["in"] == "header"
    assert parameters["Authorization"]["required"] is True
    schema_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert schema_ref.endswith("/M2LinkCareContextOnCareContextPayload")
