import json
import asyncio
import time

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes import abdm as abdm_routes
from app.main import create_app
from app.settings import settings
from app.core.constants import HEADER_HMAC_SIGNATURE, HEADER_HMAC_TIMESTAMP
from app.security.hmac import HMACValidator
from app.orchestration.abha_state import abha_workflow_store
from app.abdm.json_storage import reset_json_storage


def _reset_workflow_store() -> None:
    reset_json_storage()
    abha_workflow_store._by_correlation.clear()
    abha_workflow_store._request_to_correlation.clear()
    abha_workflow_store._consent_to_correlation.clear()
    abha_workflow_store._transaction_to_correlation.clear()


def _configure_test_settings() -> None:
    settings.ABDM_CALLBACK_AUTH_MODE = "hmac"
    settings.ABDM_CALLBACK_HMAC_SECRET = "test-secret"
    settings.ABDM_CALLBACK_HMAC_TOLERANCE_SECONDS = 300
    settings.ABDM_CALLBACK_IP_WHITELIST = ""
    settings.ENFORCE_REGION_HEADER = False
    settings.REQUIRE_AUTHORIZATION_HEADER = False
    settings.REQUIRE_JWT_VALIDATION = False
    settings.ABDM_LINKAGE_MONGO_ENABLED = False


def _build_hmac_headers(body: bytes, path: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    signature = HMACValidator.generate_signature(
        method="POST",
        path=path,
        timestamp=timestamp,
        body=body,
        secret=settings.ABDM_CALLBACK_HMAC_SECRET,
    )
    return {
        HEADER_HMAC_TIMESTAMP: timestamp,
        HEADER_HMAC_SIGNATURE: signature,
        "Content-Type": "application/json",
        "X-CM-ID": settings.ABDM_CM_ID,
    }


@pytest.mark.asyncio
async def test_consent_notification_requires_hmac_headers() -> None:
    _reset_workflow_store()
    _configure_test_settings()
    app = create_app()

    payload = {
        "correlationId": "corr-1",
        "consentId": "cons-1",
        "notification": {
            "status": "GRANTED",
            "transactionId": "txn-1",
            "patient": {"id": "patient@abdm"},
            "hip": {"id": "HIP_1"},
            "hiu": {"id": "HIU_1"},
            "careContexts": [{"patientReference": "REF001", "careContextReference": "CC001"}],
            "purpose": {"text": "Treatment"},
            "permission": {
                "accessMode": "VIEW",
                "dateRange": {
                    "from": "2026-05-19T09:00:00Z",
                    "to": "2026-05-20T09:00:00Z",
                },
                "dataEraseAt": "2026-06-19T09:00:00Z",
            },
        },
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"{settings.API_V1_STR}/consent/notification",
            content=body,
            headers={"Content-Type": "application/json", "X-CM-ID": settings.ABDM_CM_ID},
        )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_consent_notification_hmac_ok_and_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset_workflow_store()
    _configure_test_settings()
    settings.ABDM_HIP_ID = "HIP_2"

    async def fake_upsert_consent(**kwargs: dict) -> dict:
        return kwargs
    monkeypatch.setattr(abdm_routes.consent_repository, "upsert_consent", fake_upsert_consent)

    app = create_app()

    await abha_workflow_store.upsert_request(
        correlation_id="corr-2",
        payload={
            "abhaAddress": "patient@abdm",
            "patient": [
                {
                    "referenceNumber": "REF001",
                    "display": "Visit 1",
                    "careContexts": [{"referenceNumber": "CC001", "display": "Prescription"}],
                }
            ],
        },
    )

    payload = {
        "correlationId": "corr-2",
        "consentId": "cons-2",
        "notification": {
            "status": "GRANTED",
            "transactionId": "txn-2",
            "patient": {"id": "patient@abdm"},
            "hip": {"id": "HIP_2"},
            "hiu": {"id": "HIU_2"},
            "careContexts": [{"patientReference": "REF001", "careContextReference": "CC001"}],
            "purpose": {"text": "Treatment"},
            "permission": {
                "accessMode": "VIEW",
                "dateRange": {
                    "from": "2026-05-19T09:00:00Z",
                    "to": "2026-05-20T09:00:00Z",
                },
                "dataEraseAt": "2026-06-19T09:00:00Z",
            },
        },
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    path = f"{settings.API_V1_STR}/consent/notification"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = _build_hmac_headers(body, path)
        response = await client.post(path, content=body, headers=headers)
        assert response.status_code == 200
        assert response.json()["acknowledgement"]["status"] == "OK"

        await asyncio.sleep(1)
        headers = _build_hmac_headers(body, path)
        response = await client.post(path, content=body, headers=headers)
        assert response.status_code == 200

    record = await abha_workflow_store.get("corr-2")
    assert record is not None
    event_types = [event["type"] for event in record.get("events", [])]
    assert event_types.count("consent_notification") == 1
