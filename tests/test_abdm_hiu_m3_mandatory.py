from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.dependencies import set_abdm_gateway_client
from app.main import create_app
from app.orchestration.abha_state import abha_workflow_store
from app.settings import settings
from app.abdm.json_storage import reset_json_storage


class StubABDMGatewayClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

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
                "participant_id": participant_id,
                "participant_type": participant_type,
                "extra_headers": extra_headers or {},
                "include_auth_header": include_auth_header,
            }
        )
        if path == settings.ABDM_M3_HEALTH_INFO_REQUEST_PATH:
            return {"transactionId": "txn-id"}
        return {"requestId": body.get("requestId"), "acknowledgement": "OK"}


def _reset_workflow_store() -> None:
    reset_json_storage()
    abha_workflow_store._by_correlation.clear()
    abha_workflow_store._request_to_correlation.clear()
    abha_workflow_store._consent_to_correlation.clear()
    abha_workflow_store._transaction_to_correlation.clear()


def _configure_test_settings() -> None:
    settings.ENFORCE_REGION_HEADER = False
    settings.REQUIRE_AUTHORIZATION_HEADER = False
    settings.REQUIRE_JWT_VALIDATION = False
    settings.ENABLE_ABHA = True
    settings.REGION = "india"
    settings.ABDM_CALLBACK_AUTH_MODE = "none"
    settings.ABDM_CM_ID = "sbx"
    settings.ABDM_HIU_ID = "HIU_11"
    settings.ABDM_PARTICIPANT_ID = "HIU_11"
    settings.ABDM_PARTICIPANT_TYPE = "HIU"
    settings.GATEWAY_DEFAULT_DATA_PUSH_URL = "https://example.test/health-information/notify"
    settings.ABDM_M3_CONSENT_REQUEST_INIT_PATH = "/consent-requests/init"
    settings.ABDM_M3_CONSENT_FETCH_PATH = "/consents/fetch"
    settings.ABDM_M3_HEALTH_INFO_REQUEST_PATH = "/health-information/request"
    settings.ABDM_M3_HEALTH_INFO_CM_NOTIFY_PATH = "/health-information/cm/notify"


@pytest.mark.asyncio
async def test_hiu_m3_mandatory_outbound_apis_generate_metadata_and_headers() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    stub = StubABDMGatewayClient()
    app = create_app()

    consent_payload = {
        "consent": {
            "patient": {"id": "patient@sbx"},
            "purpose": {"code": "CAREMGMT", "text": "Care Management"},
            "hiTypes": ["Prescription"],
            "hiu": {"id": "HIU_11"},
            "hip": {"id": "HIP_11"},
            "requester": {"name": "Dr. John Doe"},
            "permission": {
                "accessMode": "VIEW",
                "dateRange": {"from": "2026-08-01T00:00:00Z", "to": "2026-12-31T23:59:59Z"},
                "dataEraseAt": "2027-01-31T23:59:59Z",
            },
        }
    }
    health_payload = {
        "hiRequest": {
            "consent": {"id": "consent-artifact-id"},
            "dateRange": {"from": "2025-01-01T00:00:00Z", "to": "2025-12-31T23:59:59Z"},
            "keyMaterial": {
                "dhPublicKey": {"keyValue": "PUBLIC_KEY"},
                "nonce": "RANDOM_NONCE",
            },
        }
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        consent_response = await client.post(f"{settings.API_V1_STR}/consent-requests/init", json=consent_payload)
        fetch_response = await client.post(
            f"{settings.API_V1_STR}/consents/fetch",
            json={"consentId": "consent-artifact-id"},
        )
        hi_response = await client.post(f"{settings.API_V1_STR}/health-information/request", json=health_payload)
        notify_response = await client.post(
            f"{settings.API_V1_STR}/health-information/cm/notify",
            json={"transactionId": "txn-id", "status": "SUCCESS"},
        )

    assert [consent_response.status_code, fetch_response.status_code, hi_response.status_code, notify_response.status_code] == [
        200,
        200,
        200,
        200,
    ]
    assert [call["path"] for call in stub.calls] == [
        settings.ABDM_M3_CONSENT_REQUEST_INIT_PATH,
        settings.ABDM_M3_CONSENT_FETCH_PATH,
        settings.ABDM_M3_HEALTH_INFO_REQUEST_PATH,
        settings.ABDM_M3_HEALTH_INFO_CM_NOTIFY_PATH,
    ]
    assert all(call["participant_type"] == "HIU" for call in stub.calls)
    assert all(call["participant_id"] == "HIU_11" for call in stub.calls)
    for call in stub.calls:
        UUID(call["body"]["requestId"])
        assert call["body"]["timestamp"].endswith("Z")
        assert call["extra_headers"]["REQUEST-ID"] == call["body"]["requestId"]
        assert call["extra_headers"]["TIMESTAMP"] == call["body"]["timestamp"]
        assert call["extra_headers"]["X-CM-ID"] == "sbx"
        assert call["extra_headers"]["X-HIU-ID"] == "HIU_11"

    assert stub.calls[0]["body"]["consent"]["hiu"]["id"] == "HIU_11"
    assert stub.calls[2]["body"]["hiRequest"]["dataPushUrl"] == settings.GATEWAY_DEFAULT_DATA_PUSH_URL
    assert stub.calls[2]["body"]["hiRequest"]["keyMaterial"]["cryptoAlg"] == "ECDH"


@pytest.mark.asyncio
async def test_hiu_m3_mandatory_callbacks_acknowledge_ok() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        on_init = await client.post(
            f"{settings.API_V1_STR}/consent-requests/on-init",
            json={
                "requestId": "req-1",
                "timestamp": "2026-05-27T10:10:00Z",
                "consentRequest": {
                    "id": "consent-request-id",
                    "status": "GRANTED",
                    "consentArtefacts": [{"id": "consent-artifact-id"}],
                },
            },
            headers={"X-CM-ID": "sbx"},
        )
        on_fetch = await client.post(
            f"{settings.API_V1_STR}/consents/on-fetch",
            json={"requestId": "req-1", "consentArtefact": {"id": "consent-artifact-id", "status": "ACTIVE"}},
            headers={"X-CM-ID": "sbx"},
        )
        on_request = await client.post(
            f"{settings.API_V1_STR}/health-information/on-request",
            json={
                "requestId": "req-1",
                "hiRequest": {"transactionId": "txn-id", "sessionStatus": "REQUESTED"},
            },
            headers={"X-CM-ID": "sbx"},
        )
        notify = await client.post(
            f"{settings.API_V1_STR}/health-information/data",
            json={
                "transactionId": "txn-id",
                "entries": [
                    {
                        "content": "eyJmaGlyIjogImJ1bmRsZSJ9",
                        "media": "application/fhir+json",
                        "checksum": "dummy-checksum",
                        "careContextReference": "CC001",
                    }
                ],
                "keyMaterial": {
                    "nonce": "NONCE",
                    "dhPublicKey": {
                        "expiry": "2026-12-31T23:59:59Z",
                        "parameters": "Curve25519/32byte random key",
                        "keyValue": "dummy-pubkey",
                    }
                },
            },
            headers={"X-CM-ID": "sbx"},
        )

    assert on_init.json() == {"acknowledgement": {"status": "OK"}}
    assert on_fetch.json() == {"acknowledgement": {"status": "OK"}}
    assert on_request.json() == {"acknowledgement": {"status": "OK"}}
    assert notify.json() == {"status": "DELIVERED"}


@pytest.mark.asyncio
async def test_hiu_consent_request_init_validation_failures() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    app = create_app()

    async def post_init(payload: dict):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            return await client.post(f"{settings.API_V1_STR}/consent-requests/init", json=payload)

    # 1. Invalid ABHA Address format (missing @)
    p = {
        "consent": {
            "patient": {"id": "invalidaddress"},
            "purpose": {"code": "CAREMGMT", "text": "Care"},
            "hiTypes": ["Prescription"],
            "hiu": {"id": "HIU_11"},
            "hip": {"id": "HIP_11"},
            "requester": {"name": "Doc"},
            "permission": {
                "accessMode": "VIEW",
                "dateRange": {"from": "2026-08-01T00:00:00Z", "to": "2026-12-31T23:59:59Z"},
                "dataEraseAt": "2027-01-31T23:59:59Z",
            },
        }
    }
    r = await post_init(p)
    assert r.status_code == 400
    assert "ABHA Address format" in r.json()["detail"]

    # 2. Empty HIU ID
    p["consent"]["patient"]["id"] = "patient@sbx"
    p["consent"]["hiu"]["id"] = ""
    r = await post_init(p)
    assert r.status_code == 400
    assert "HIU ID" in r.json()["detail"]

    # 3. Empty HIP ID
    p["consent"]["hiu"]["id"] = "HIU_11"
    p["consent"]["hip"]["id"] = "   "
    r = await post_init(p)
    assert r.status_code == 400
    assert "HIP ID" in r.json()["detail"]

    # 4. Expired date range
    p["consent"]["hip"]["id"] = "HIP_11"
    p["consent"]["permission"]["dateRange"] = {"from": "2020-01-01T00:00:00Z", "to": "2021-01-01T00:00:00Z"}
    r = await post_init(p)
    assert r.status_code == 400
    assert "expired" in r.json()["detail"]

    # 5. Invalid dataEraseAt (past date)
    p["consent"]["permission"]["dateRange"] = {"from": "2026-08-01T00:00:00Z", "to": "2026-12-31T23:59:59Z"}
    p["consent"]["permission"]["dataEraseAt"] = "2020-01-01T00:00:00Z"
    r = await post_init(p)
    assert r.status_code == 400
    assert "dataEraseAt" in r.json()["detail"]


@pytest.mark.asyncio
async def test_hiu_gateway_client_503_diagnostics() -> None:
    from app.abdm.client import ABDMGatewayClient
    from app.abdm.auth import ABDMAuthService
    from unittest.mock import AsyncMock, patch
    import httpx
    from fastapi import HTTPException

    auth_service = AsyncMock(spec=ABDMAuthService)
    auth_service.get_token.return_value = "token"

    client = ABDMGatewayClient(auth_service)

    mock_response = httpx.Response(
        status_code=503,
        content=b"Service Unavailable Details",
        request=httpx.Request("POST", "http://test/consent-requests/init")
    )

    with patch("app.abdm.client._send_with_transient_retries", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = mock_response

        with pytest.raises(HTTPException) as exc_info:
            await client.post("consent-requests/init", {"requestId": "foo"})

        assert exc_info.value.status_code == 503
        detail = exc_info.value.detail
        assert "503 Service Unavailable" in detail["message"]
        assert detail["requestId"] is not None
        assert detail["correlationId"] is not None
        assert detail["responseBody"] == "Service Unavailable Details"

