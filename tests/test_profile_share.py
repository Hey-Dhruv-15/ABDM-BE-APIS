import pytest
from httpx import ASGITransport, AsyncClient
from datetime import datetime, timezone
from uuid import UUID

from app.api.dependencies import set_abdm_gateway_client
from app.main import create_app
from app.settings import settings
from app.orchestration.abha_state import abha_workflow_store

class StubABDMGatewayClient:
    async def post(self, *args, **kwargs):
        return {"status": "Accepted"}

def _configure_test_settings() -> None:
    settings.ENFORCE_REGION_HEADER = False
    settings.REQUIRE_AUTHORIZATION_HEADER = False
    settings.REQUIRE_JWT_VALIDATION = False
    settings.ENABLE_ABHA = True
    settings.REGION = "india"
    settings.ABDM_CM_ID = "sbx"
    settings.ABDM_INTEGRATION_ID = "test-relay"
    settings.ABDM_CALLBACK_AUTH_MODE = "none"

def _reset_workflow_store() -> None:
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

@pytest.mark.asyncio
async def test_profile_share_success() -> None:
    _configure_test_settings()
    _reset_workflow_store()
    
    app = create_app()
    stub = StubABDMGatewayClient()
    
    payload = {
        "acknowledgement": {
            "abhaAddress": "91565612325177@sbx",
            "status": "success",
            "profile": {
                "context": "1",
                "tokenNumber": "1001",
                "expiry": "180"
            }
        },
        "response": {
            "requestId": "550e8400-e29b-41d4-a716-446655440000"
        }
    }
    
    # Pre-index the request in the workflow store so resolve_correlation works
    await abha_workflow_store.upsert_request(
        correlation_id="correlation-123",
        consent_request_id="550e8400-e29b-41d4-a716-446655440000",
        event_type="request",
    )
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        set_abdm_gateway_client(stub)
        response = await client.post(
            f"{settings.API_V1_STR}/profile/share",
            json=payload,
            headers=_m2_headers(),
        )
        
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["acknowledgement"]["status"] == "OK"
    assert res_data["requestId"] == "550e8400-e29b-41d4-a716-446655440000"
    assert res_data["abhaAddress"] == "91565612325177@sbx"
    assert res_data["receivedEntries"] == 1
    # Check timestamp format
    assert datetime.fromisoformat(res_data["timestamp"]) is not None
    
    # Verify the workflow store was updated
    record = await abha_workflow_store.get("correlation-123")
    assert record is not None
    assert record["abha_address"] == "91565612325177@sbx"
    # Find the profile_share event in events
    events = record["events"]
    profile_share_event = next(e for e in events if e["type"] == "profile_share")
    assert profile_share_event["payload"]["acknowledgement"]["status"] == "success"


@pytest.mark.asyncio
async def test_profile_share_validation_failure_missing_fields() -> None:
    _configure_test_settings()
    app = create_app()
    
    # Missing profile details
    payload = {
        "acknowledgement": {
            "abhaAddress": "91565612325177@sbx",
            "status": "success"
        },
        "response": {
            "requestId": "550e8400-e29b-41d4-a716-446655440000"
        }
    }
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"{settings.API_V1_STR}/profile/share",
            json=payload,
            headers=_m2_headers(),
        )
        
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_profile_share_validation_failure_extra_fields() -> None:
    _configure_test_settings()
    app = create_app()
    
    # Extra prop in profile
    payload = {
        "acknowledgement": {
            "abhaAddress": "91565612325177@sbx",
            "status": "success",
            "profile": {
                "context": "1",
                "tokenNumber": "1001",
                "expiry": "180",
                "extraProp": "invalid"
            }
        },
        "response": {
            "requestId": "550e8400-e29b-41d4-a716-446655440000"
        }
    }
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"{settings.API_V1_STR}/profile/share",
            json=payload,
            headers=_m2_headers(),
        )
        
    assert response.status_code == 422
