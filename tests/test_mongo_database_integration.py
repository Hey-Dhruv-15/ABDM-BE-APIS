"""
Pytest integration tests for MongoDB database endpoints and collections
"""
import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.db.mongo_manager import MongoDBManager

HEADERS = {
    "X-Region": "india",
    "Authorization": "Bearer test-jwt-token"
}

@pytest.fixture(autouse=True)
def setup_mongo_data():
    """Ensure MongoDB has seeded data for tests."""
    MongoDBManager.seed_initial_data()


@pytest.mark.anyio
async def test_get_consent_requests_mongo():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/consent-requests", headers=HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "records" in data
        assert data["total"] >= 1


@pytest.mark.anyio
async def test_get_audit_logs_mongo():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/audit-logs?milestone=ALL", headers=HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "records" in data
        assert data["total"] >= 1


@pytest.mark.anyio
async def test_get_audit_logs_filtered_m3():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/audit-logs?milestone=M3", headers=HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "records" in data


@pytest.mark.anyio
async def test_mongo_clinical_records_query():
    records = MongoDBManager.fetch_raw_clinical_records(patient_id="sroshan110707@sbx")
    assert len(records) >= 1
    hi_types = [r.get("hi_type") for r in records]
    assert "Prescription" in hi_types or "DiagnosticReport" in hi_types
