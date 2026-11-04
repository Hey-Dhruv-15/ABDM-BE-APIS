import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.abdm.json_storage import update_entry

HEADERS = {"X-Region": "india", "Authorization": "Bearer test-token"}

@pytest.fixture(autouse=True)
def setup_test_consent_data():
    """Seed test consent data in consent_requests.json storage."""
    update_entry("consent_requests", "CONS-TEST-001", {
        "requestId": "CONS-TEST-001",
        "consentRequestId": "CONS-TEST-001",
        "status": "REQUESTED",
        "patient": {"id": "sroshan110707@sbx", "name": "Roshan S"},
        "consent": {
            "purpose": {"text": "Care Management", "code": "CAREMGT"},
            "patient": {"id": "sroshan110707@sbx"},
            "hiTypes": ["Prescription", "DiagnosticReport"],
            "permission": {
                "accessMode": "VIEW",
                "dateRange": {"from": "2025-01-01T00:00:00.000Z", "to": "2026-09-02T23:59:59.000Z"},
                "dataEraseAt": "2027-06-19T09:00:00.000Z",
            }
        },
        "timestamp": "2026-08-21T12:00:00.000Z"
    })

    update_entry("consent_requests", "CONS-TEST-002", {
        "requestId": "CONS-TEST-002",
        "consentRequestId": "CONS-TEST-002",
        "consentArtifactId": "CONSENT-ART-99201",
        "status": "GRANTED",
        "patient": {"id": "rahul.m@sbx", "name": "Rahul M"},
        "consent": {
            "id": "CONSENT-ART-99201",
            "purpose": {"text": "Care Management", "code": "CAREMGT"},
            "patient": {"id": "rahul.m@sbx"},
            "hiTypes": ["OPConsultation", "LabReport"],
            "permission": {
                "accessMode": "STORE",
                "dateRange": {"from": "2025-01-01T00:00:00.000Z", "to": "2026-09-02T23:59:59.000Z"},
                "dataEraseAt": "2027-06-19T09:00:00.000Z",
            }
        },
        "timestamp": "2026-08-22T14:30:00.000Z"
    })


@pytest.mark.anyio
async def test_list_consent_requests():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/consent-requests", headers=HEADERS)
        assert res.status_code == 200, f"Error: {res.text}"
        data = res.json()
        assert data["status"] == "ok"
        assert "records" in data
        assert len(data["records"]) >= 2


@pytest.mark.anyio
async def test_list_consent_requests_filter_by_status():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/consent-requests?status=GRANTED", headers=HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        for item in data["records"]:
            assert item["status"] == "GRANTED"


@pytest.mark.anyio
async def test_list_consent_requests_search():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/consent-requests?search=sroshan", headers=HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert any(item["consentRequestId"] == "CONS-TEST-001" for item in data["records"])


@pytest.mark.anyio
async def test_get_consent_request_details():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/consent-requests/CONS-TEST-001", headers=HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["consentRequestId"] == "CONS-TEST-001"
        assert data["patient"]["id"] == "sroshan110707@sbx"


@pytest.mark.anyio
async def test_cancel_consent_request():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/api/v1/consent-requests/CONS-TEST-001/cancel", headers=HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["newStatus"] == "CANCELLED"

        res_details = await ac.get("/api/v1/consent-requests/CONS-TEST-001", headers=HEADERS)
        assert res_details.json()["statusValue"] == "CANCELLED"


@pytest.mark.anyio
async def test_prefill_re_request_consent():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/api/v1/consent-requests/CONS-TEST-002/re-request", headers=HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
