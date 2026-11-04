import asyncio
import json
import base64
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx

from app.settings import settings
from app.abdm.json_storage import read_storage, update_entry, reset_json_storage
from app.abdm.client import ABDMGatewayClient
from app.api.dependencies import set_abdm_auth_service, set_abdm_gateway_client
from app.main import create_app

def log(msg=""):
    print(msg, flush=True)

def create_jwt(claims: dict, expired: bool = False) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = datetime.now(timezone.utc)
    if expired:
        claims["exp"] = int((now - timedelta(hours=2)).timestamp())
        claims["iat"] = int((now - timedelta(hours=3)).timestamp())
    else:
        claims["exp"] = int((now + timedelta(hours=2)).timestamp())
        claims["iat"] = int(now.timestamp())

    def b64url(val: dict) -> str:
        s = json.dumps(val, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(s).decode("utf-8").rstrip("=")

    h_b64 = b64url(header)
    c_b64 = b64url(claims)
    sig = "dummy_signature_bytes_1234567890"
    return f"{h_b64}.{c_b64}.{sig}"


class MockAuthService:
    async def get_token(self, force_refresh: bool = False) -> str:
        return "mock-gw-session-token"

    def token_expiry(self):
        return datetime.now(timezone.utc) + timedelta(hours=1)


class MockGatewayClient:
    def __init__(self):
        self.calls = []

    async def get(self, path, **kwargs):
        self.calls.append({"method": "GET", "path": path, **kwargs})
        return {"status": "ok"}

    async def post(self, path, body=None, **kwargs):
        self.calls.append({"method": "POST", "path": path, "body": body, **kwargs})
        return {"status": "Accepted", "requestId": str(uuid4())}

    async def patch(self, path, body=None, **kwargs):
        self.calls.append({"method": "PATCH", "path": path, "body": body, **kwargs})
        return {"status": "Accepted", "url": body.get("url") if body else ""}

    async def put(self, path, body=None, **kwargs):
        self.calls.append({"method": "PUT", "path": path, "body": body, **kwargs})
        return {"status": "Accepted"}


async def run_all_validations():
    results = {}
    log("=" * 80)
    log("STARTING COMPREHENSIVE ABDM API VALIDATION SUITE")
    log("=" * 80)

    # 1. Test ABDMGatewayClient.patch()
    log("\n--- TEST 1: ABDMGatewayClient.patch() method ---")
    mock_auth = MockAuthService()
    gw_client = ABDMGatewayClient(mock_auth)
    has_patch = hasattr(gw_client, "patch") and callable(getattr(gw_client, "patch"))
    if has_patch:
        log("[PASS] ABDMGatewayClient has callable patch() method")
        results["ABDMGatewayClient.patch()"] = "PASS"
    else:
        log("[FAIL] ABDMGatewayClient is missing patch() method")
        results["ABDMGatewayClient.patch()"] = "FAIL"

    # Setup App for ASGI testing
    settings.CONFIG_WATCH_ENABLED = False
    settings.ABDM_BRIDGE_URL = ""
    settings.GATEWAY_DEFAULT_DATA_PUSH_URL = ""
    settings.REQUIRE_AUTHORIZATION_HEADER = False
    settings.ENFORCE_REGION_HEADER = False

    reset_json_storage()
    mock_gw = MockGatewayClient()
    set_abdm_auth_service(mock_auth)
    set_abdm_gateway_client(mock_gw)

    app = create_app()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        base_hdrs = {
            "REQUEST-ID": str(uuid4()),
            "TIMESTAMP": datetime.now(timezone.utc).isoformat(),
            "X-CM-ID": "sbx",
            "X-Region": "india",
            "X-Integration": "test-relay",
            "Content-Type": "application/json",
        }

        # -------------------------------------------------------------
        # TEST 2: HIP token callback 404 fix
        # -------------------------------------------------------------
        log("\n--- TEST 2: HIP Token Callbacks (No 404) ---")
        token_jwt = create_jwt({"abhaAddress": "testuser@sbx", "hipId": "IN2810014366"})
        cb_payload = {
            "requestId": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "token": token_jwt,
            "response": {"requestId": "orig-req-12345"}
        }

        # 2a. POST /api/v3/hip/token/on-generate-token
        res1 = await client.post("/api/v3/hip/token/on-generate-token", json=cb_payload, headers=base_hdrs)
        log(f"POST /api/v3/hip/token/on-generate-token -> Status: {res1.status_code}")
        if res1.status_code == 200 and res1.json().get("acknowledgement", {}).get("status") == "OK":
            log("[PASS] /api/v3/hip/token/on-generate-token handled successfully (200 OK)")
            results["POST /api/v3/hip/token/on-generate-token"] = "PASS"
        else:
            log(f"[FAIL] /api/v3/hip/token/on-generate-token returned {res1.status_code}: {res1.text}")
            results["POST /api/v3/hip/token/on-generate-token"] = "FAIL"

        # 2b. POST /v3/hip/token/on-generate-token (root level)
        res2 = await client.post("/v3/hip/token/on-generate-token", json=cb_payload, headers=base_hdrs)
        log(f"POST /v3/hip/token/on-generate-token -> Status: {res2.status_code}")
        if res2.status_code == 200 and res2.json().get("acknowledgement", {}).get("status") == "OK":
            log("[PASS] /v3/hip/token/on-generate-token handled successfully (200 OK)")
            results["POST /v3/hip/token/on-generate-token"] = "PASS"
        else:
            log(f"[FAIL] /v3/hip/token/on-generate-token returned {res2.status_code}: {res2.text}")
            results["POST /v3/hip/token/on-generate-token"] = "FAIL"

        # Verify token was saved in link_tokens storage
        saved_entry = read_storage("link_tokens")
        if "testuser@sbx" in saved_entry and saved_entry["testuser@sbx"].get("linkToken") == token_jwt:
            log("[PASS] Link token properly saved to local link_tokens storage for testuser@sbx")
            results["Link Token Storage Persistence"] = "PASS"
        else:
            log(f"[FAIL] Link token not found in storage: {saved_entry}")
            results["Link Token Storage Persistence"] = "FAIL"

        # -------------------------------------------------------------
        # TEST 3: Care-Context Linking Scenarios
        # -------------------------------------------------------------
        log("\n--- TEST 3: Care-Context Linking Scenarios ---")
        link_url = f"{settings.API_V1_STR}/hiecm/hip/v3/link/carecontext"
        valid_auth_hdr = f"Bearer {create_jwt({'sub': 'SBX_006916'})}"
        valid_link_jwt = create_jwt({"abhaAddress": "testuser@sbx", "hipId": "IN2810014366"})
        expired_link_jwt = create_jwt({"abhaAddress": "testuser@sbx", "hipId": "IN2810014366"}, expired=True)
        expired_auth_jwt = f"Bearer {create_jwt({'sub': 'SBX_006916'}, expired=True)}"
        invalid_jwt_hdr = "Bearer header.invalid_base64_part.sig"

        care_context_payload = {
            "abhaNumber": "91687401063254",
            "abhaAddress": "testuser@sbx",
            "patient": [
                {
                    "referenceNumber": "REF001",
                    "display": "Visit #1 & Consultation",
                    "careContexts": [
                        {
                            "referenceNumber": "CC001",
                            "display": "Prescription #1"
                        }
                    ],
                    "hiType": "Prescription",
                    "count": 1
                }
            ]
        }

        # 3a. Valid link token & valid auth -> Success
        hdrs_valid = {
            **base_hdrs,
            "Authorization": valid_auth_hdr,
            "X-LINK-TOKEN": valid_link_jwt,
            "X-HIP-ID": "IN2810014366",
        }
        res_link_valid = await client.post(link_url, json=care_context_payload, headers=hdrs_valid)
        log(f"3a. Valid Link Token -> Status: {res_link_valid.status_code}")
        if res_link_valid.status_code in (200, 202):
            log(f"[PASS] Care-context linked successfully (Status: {res_link_valid.status_code})")
            results["Care-Context Link (Valid Token)"] = "PASS"
        else:
            log(f"[FAIL] Expected 200/202, got {res_link_valid.status_code}: {res_link_valid.text}")
            results["Care-Context Link (Valid Token)"] = "FAIL"

        # 3b. Missing X-LINK-TOKEN -> 400 Bad Request
        hdrs_missing = {
            **base_hdrs,
            "Authorization": valid_auth_hdr,
            "X-HIP-ID": "IN2810014366",
        }
        reset_json_storage()
        res_missing = await client.post(link_url, json=care_context_payload, headers=hdrs_missing)
        log(f"3b. Missing X-LINK-TOKEN -> Status: {res_missing.status_code}")
        if res_missing.status_code == 400 and "X-LINK-TOKEN header missing" in res_missing.text:
            log("[PASS] Missing X-LINK-TOKEN properly rejected with 400")
            results["Care-Context Link (Missing Token -> 400)"] = "PASS"
        else:
            log(f"[FAIL] Expected 400, got {res_missing.status_code}: {res_missing.text}")
            results["Care-Context Link (Missing Token -> 400)"] = "FAIL"

        # 3c. Expired X-LINK-TOKEN -> 401 Unauthorized
        hdrs_exp_link = {
            **base_hdrs,
            "Authorization": valid_auth_hdr,
            "X-LINK-TOKEN": expired_link_jwt,
            "X-HIP-ID": "IN2810014366",
        }
        res_exp_link = await client.post(link_url, json=care_context_payload, headers=hdrs_exp_link)
        log(f"3c. Expired X-LINK-TOKEN -> Status: {res_exp_link.status_code}")
        if res_exp_link.status_code == 401 and "expired" in res_exp_link.text:
            log("[PASS] Expired X-LINK-TOKEN properly rejected with 401")
            results["Care-Context Link (Expired Link Token -> 401)"] = "PASS"
        else:
            log(f"[FAIL] Expected 401, got {res_exp_link.status_code}: {res_exp_link.text}")
            results["Care-Context Link (Expired Link Token -> 401)"] = "FAIL"

        # 3d. Expired Bearer Authorization token -> 401 Unauthorized
        hdrs_exp_auth = {
            **base_hdrs,
            "Authorization": expired_auth_jwt,
            "X-LINK-TOKEN": valid_link_jwt,
            "X-HIP-ID": "IN2810014366",
        }
        res_exp_auth = await client.post(link_url, json=care_context_payload, headers=hdrs_exp_auth)
        log(f"3d. Expired Authorization Token -> Status: {res_exp_auth.status_code}")
        if res_exp_auth.status_code == 401 and "expired" in res_exp_auth.text:
            log("[PASS] Expired Authorization token properly rejected with 401")
            results["Care-Context Link (Expired Auth Token -> 401)"] = "PASS"
        else:
            log(f"[FAIL] Expected 401, got {res_exp_auth.status_code}: {res_exp_auth.text}")
            results["Care-Context Link (Expired Auth Token -> 401)"] = "FAIL"

        # 3e. Invalid JWT format in Bearer token -> 401 Unauthorized
        hdrs_inv_jwt = {
            **base_hdrs,
            "Authorization": invalid_jwt_hdr,
            "X-LINK-TOKEN": valid_link_jwt,
            "X-HIP-ID": "IN2810014366",
        }
        res_inv_jwt = await client.post(link_url, json=care_context_payload, headers=hdrs_inv_jwt)
        log(f"3e. Invalid JWT in Authorization -> Status: {res_inv_jwt.status_code}")
        if res_inv_jwt.status_code == 401 and "valid JWT" in res_inv_jwt.text:
            log("[PASS] Invalid JWT properly rejected with 401")
            results["Care-Context Link (Invalid JWT -> 401)"] = "PASS"
        else:
            log(f"[FAIL] Expected 401, got {res_inv_jwt.status_code}: {res_inv_jwt.text}")
            results["Care-Context Link (Invalid JWT -> 401)"] = "FAIL"

        # 3f. Payload display sanitization test
        last_call = mock_gw.calls[-1] if mock_gw.calls else {}
        forwarded_body = last_call.get("body") or {}
        patient_entries = forwarded_body.get("patient") or []
        if patient_entries:
            p_display = patient_entries[0].get("display", "")
            cc_display = patient_entries[0].get("careContexts", [{}])[0].get("display", "")
            log(f"3f. Forwarded Sanitized patient.display: '{p_display}'")
            log(f"3f. Forwarded Sanitized careContext.display: '{cc_display}'")
            if "#" not in p_display and "&" not in p_display and "#" not in cc_display:
                log("[PASS] Payload display fields successfully sanitized")
                results["Payload Display Sanitization"] = "PASS"
            else:
                log(f"[FAIL] Prohibited characters still in display: {p_display}, {cc_display}")
                results["Payload Display Sanitization"] = "FAIL"

        # -------------------------------------------------------------
        # TEST 4: Consent Callback Scenarios (GRANTED, DENIED, EXPIRED)
        # -------------------------------------------------------------
        log("\n--- TEST 4: Consent Callbacks & ID Mapping ---")
        client_req_id = str(uuid4())
        gateway_consent_id = "GATEWAY-CONSENT-REQ-998877"

        # 4a. Initialize a consent request
        init_payload = {
            "requestId": client_req_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "consent": {
                "purpose": {"text": "Care Management", "code": "CAREMGT"},
                "patient": {"id": "testpatient@sbx", "name": "Test Patient"},
                "hiu": {"id": "IN2910002345"},
                "requester": {"name": "Dr. Smith"},
                "hiTypes": ["Prescription"],
                "permission": {
                    "accessMode": "VIEW",
                    "dateRange": {"from": "2025-01-01T00:00:00.000Z", "to": "2026-12-31T23:59:59.000Z"},
                    "dataEraseAt": "2027-12-31T23:59:59.000Z",
                    "frequency": {"unit": "HOUR", "value": 1, "repeats": 0}
                }
            }
        }
        res_c_init = await client.post(f"{settings.API_V1_STR}/consent-requests/init", json=init_payload, headers=base_hdrs)
        log(f"4a. Consent Request Init -> Status: {res_c_init.status_code}")
        stored_init = read_storage("consent_requests")
        if client_req_id in stored_init:
            log("[PASS] Consent request stored in local JSON storage as REQUESTED")
            results["Consent Request Init"] = "PASS"
        else:
            log(f"[FAIL] Consent request not in storage: {stored_init}")
            results["Consent Request Init"] = "FAIL"

        # 4b. On-Init callback from ABDM mapping gateway ID to client requestId
        on_init_cb = {
            "requestId": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "consentRequest": {
                "id": gateway_consent_id,
                "status": "REQUESTED"
            },
            "resp": {
                "requestId": client_req_id
            }
        }
        res_on_init = await client.post("/api/v3/hiu/consent/request/on-init", json=on_init_cb, headers=base_hdrs)
        log(f"4b. On-Init Callback -> Status: {res_on_init.status_code}")
        stored_after_init = read_storage("consent_requests")
        if gateway_consent_id in stored_after_init and stored_after_init[client_req_id].get("gatewayConsentRequestId") == gateway_consent_id:
            log("[PASS] On-Init callback successfully mapped gatewayConsentRequestId to client requestId")
            results["Consent On-Init ID Mapping"] = "PASS"
        else:
            log(f"[FAIL] ID mapping failed: {stored_after_init}")
            results["Consent On-Init ID Mapping"] = "FAIL"

        # 4c. On-Init Error Callback (e.g. ABDM-1039: Invalid Consent request id)
        error_req_id = str(uuid4())
        update_entry("consent_requests", error_req_id, {"requestId": error_req_id, "status": "REQUESTED"})
        on_init_err_cb = {
            "requestId": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": {
                "code": "ABDM-1039",
                "message": "Invalid Consent request id"
            },
            "resp": {
                "requestId": error_req_id
            }
        }
        res_on_init_err = await client.post("/api/v3/hiu/consent/request/on-init", json=on_init_err_cb, headers=base_hdrs)
        log(f"4c. On-Init Error Callback (ABDM-1039) -> Status: {res_on_init_err.status_code}")
        stored_err = read_storage("consent_requests")
        if res_on_init_err.status_code == 200 and stored_err[error_req_id].get("status") == "ERROR":
            log("[PASS] On-Init error callback handled gracefully (status set to ERROR, no 422 crash)")
            results["Consent On-Init Error Handling (ABDM-1039)"] = "PASS"
        else:
            log(f"[FAIL] On-Init error handling failed: {res_on_init_err.status_code}, {stored_err.get(error_req_id)}")
            results["Consent On-Init Error Handling (ABDM-1039)"] = "FAIL"

        # 4d. Consent Notify Callback: GRANTED
        notify_granted = {
            "requestId": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notification": {
                "consentRequestId": gateway_consent_id,
                "status": "GRANTED",
                "consentArtefacts": [{"id": "ART-GRANTED-001"}]
            }
        }
        res_granted = await client.post("/api/v3/hiu/consent/request/notify", json=notify_granted, headers=base_hdrs)
        log(f"4d. Consent Notify GRANTED -> Status: {res_granted.status_code}")
        stored_granted = read_storage("consent_requests")
        if stored_granted[gateway_consent_id].get("status") == "GRANTED" and stored_granted[gateway_consent_id].get("consentArtifactId") == "ART-GRANTED-001":
            log("[PASS] Consent GRANTED callback updated status and consentArtifactId")
            results["Consent Callback (GRANTED)"] = "PASS"
        else:
            log(f"[FAIL] GRANTED update failed: {stored_granted.get(gateway_consent_id)}")
            results["Consent Callback (GRANTED)"] = "FAIL"

        # 4e. Consent Notify Callback: DENIED
        notify_denied = {
            "requestId": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notification": {
                "consentRequestId": gateway_consent_id,
                "status": "DENIED",
                "consentArtefacts": []
            }
        }
        res_denied = await client.post("/api/v3/hiu/consent/request/notify", json=notify_denied, headers=base_hdrs)
        log(f"4e. Consent Notify DENIED -> Status: {res_denied.status_code}")
        stored_denied = read_storage("consent_requests")
        if stored_denied[gateway_consent_id].get("status") == "DENIED":
            log("[PASS] Consent DENIED callback updated status to DENIED")
            results["Consent Callback (DENIED)"] = "PASS"
        else:
            log(f"[FAIL] DENIED update failed: {stored_denied.get(gateway_consent_id)}")
            results["Consent Callback (DENIED)"] = "FAIL"

        # 4f. Consent Notify Callback: EXPIRED
        notify_expired = {
            "requestId": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notification": {
                "consentRequestId": gateway_consent_id,
                "status": "EXPIRED",
                "consentArtefacts": []
            }
        }
        res_expired = await client.post("/api/v3/hiu/consent/request/notify", json=notify_expired, headers=base_hdrs)
        log(f"4f. Consent Notify EXPIRED -> Status: {res_expired.status_code}")
        stored_expired = read_storage("consent_requests")
        if stored_expired[gateway_consent_id].get("status") == "EXPIRED":
            log("[PASS] Consent EXPIRED callback updated status to EXPIRED")
            results["Consent Callback (EXPIRED)"] = "PASS"
        else:
            log(f"[FAIL] EXPIRED update failed: {stored_expired.get(gateway_consent_id)}")
            results["Consent Callback (EXPIRED)"] = "FAIL"

        # 4g. List Consent Requests endpoint (pure JSON storage without MongoDB)
        res_list = await client.get(f"{settings.API_V1_STR}/consent-requests?limit=10&sync=false")
        log(f"4g. GET /consent-requests -> Status: {res_list.status_code}")
        if res_list.status_code == 200 and res_list.json().get("status") == "ok":
            records = res_list.json().get("records", [])
            log(f"[PASS] GET /consent-requests returned {len(records)} records from JSON storage")
            results["GET /consent-requests (JSON Storage)"] = "PASS"
        else:
            log(f"[FAIL] GET /consent-requests failed: {res_list.status_code}, {res_list.text}")
            results["GET /consent-requests (JSON Storage)"] = "FAIL"

    log("\n" + "=" * 80)
    log("VALIDATION SUMMARY")
    log("=" * 80)
    all_pass = True
    for item, status in results.items():
        log(f"  {item.ljust(50)}: [{status}]")
        if status != "PASS":
            all_pass = False

    log("=" * 80)
    if all_pass:
        log("ALL TESTS PASSED! (100% SUCCESS)")
    else:
        log("SOME TESTS FAILED - REVIEW ABOVE OUTPUT")
    log("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_all_validations())
