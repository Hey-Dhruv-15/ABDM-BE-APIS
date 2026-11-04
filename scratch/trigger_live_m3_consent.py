import requests
import json
import uuid
from datetime import datetime, timezone

base_url = "http://127.0.0.1:8005"
now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
req_id = str(uuid.uuid4())

# 1. Check active ngrok tunnel
try:
    ngrok_res = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=3).json()
    
    public_url = next(
        (t["public_url"] for t in ngrok_res.get("tunnels", []) if t.get("public_url", "").startswith("https")),
        None
    )
    print(f"[TUNNEL] Detected Active Ngrok Public URL: {public_url}")
except Exception as e:
    public_url = None
    print(f"[TUNNEL ERROR] Could not read ngrok: {e}")

# 2. Register Bridge URL with ABDM Gateway
if public_url:
    print(f"\n[BRIDGE] Registering bridge URL {public_url} with ABDM Gateway...")
    bridge_headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "X-Region": "india",
        "X-CM-ID": "sbx",
        "REQUEST-ID": str(uuid.uuid4()),
        "TIMESTAMP": now_iso,
        "Authorization": "Bearer test-jwt-token-12345"
    }
    try:
        b_res = requests.patch(f"{base_url}/api/v1/hiecm/gateway/v3/bridge/url", headers=bridge_headers, json={"url": public_url}, timeout=10)
        print(f"[BRIDGE RESPONSE] Status: {b_res.status_code}, Body: {b_res.text}")
    except Exception as exc:
        print(f"[BRIDGE ERROR] {exc}")

# 3. Trigger live Consent Request Init
print(f"\n[M3 CONSENT] Sending live Consent Request Init to ABDM for sroshan110707@sbx...")
consent_headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "X-Region": "india",
    "X-CM-ID": "sbx",
    "REQUEST-ID": req_id,
    "TIMESTAMP": now_iso,
    "Authorization": "Bearer test-jwt-token-12345"
}

consent_payload = {
    "requestId": req_id,
    "timestamp": now_iso,
    "consent": {
        "purpose": {
            "text": "Care Management",
            "code": "CAREMGT",
            "refUri": "https://www.abdm.gov.in"
        },
        "patient": {
            "id": "sroshan110707@sbx"
        },
        "hip": {
            "id": "IN2910002343"
        },
        "hiu": {
            "id": "IN2910002345"
        },
        "requester": {
            "name": "Dr. Roshan",
            "identifier": {
                "type": "REGNO",
                "value": "MH1001",
                "system": "https://www.mciindia.org"
            }
        },
        "hiTypes": [
            "Prescription",
            "DiagnosticReport",
            "OPConsultation",
            "DischargeSummary",
            "ImmunizationRecord",
            "HealthDocumentRecord",
            "WellnessRecord",
            "Invoice"
        ],
        "permission": {
            "accessMode": "VIEW",
            "dateRange": {
                "from": "2025-01-01T00:00:00.000Z",
                "to": now_iso
            },
            "dataEraseAt": "2027-12-31T23:59:59.000Z",
            "frequency": {
                "unit": "HOUR",
                "value": 1,
                "repeats": 0
            }
        }
    }
}

try:
    c_res = requests.post(f"{base_url}/api/v1/consent-requests/init", headers=consent_headers, json=consent_payload, timeout=15)
    print(f"[M3 CONSENT RESPONSE] Status: {c_res.status_code}")
    print(f"[M3 CONSENT BODY]: {c_res.text}")
except Exception as e:
    print(f"[M3 CONSENT ERROR] {e}")
