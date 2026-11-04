import httpx
import json
import uuid
import datetime

def check_status_direct():
    # 1. Get session token from ABDM Gateway
    session_url = "https://dev.abdm.gov.in/api/hiecm/gateway/v3/sessions"
    session_body = {
        "clientId": "SBX_006916",
        "clientSecret": "4951ce32-0268-450f-90e9-b5478479e0bf",
        "grantType": "client_credentials"
    }
    
    with httpx.Client(timeout=30.0) as client:
        r = client.post(session_url, json=session_body)
        print("Session response:", r.status_code)
        token = r.json().get("accessToken")
        
        # 2. Call status endpoint for consentRequestId 31751474-7a07-40b6-9a7b-5b39b7ae2f0c
        status_url = "https://dev.abdm.gov.in/api/hiecm/consent/v3/request/status"
        req_id = str(uuid.uuid4())
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        headers = {
            "Authorization": f"Bearer {token}",
            "X-CM-ID": "sbx",
            "X-HIU-ID": "IN2910002345",
            "REQUEST-ID": req_id,
            "TIMESTAMP": ts,
            "Content-Type": "application/json"
        }
        
        payload = {
            "requestId": req_id,
            "timestamp": ts,
            "consentRequestId": "31751474-7a07-40b6-9a7b-5b39b7ae2f0c"
        }
        
        print(f"Sending status request for 31751474-7a07-40b6-9a7b-5b39b7ae2f0c ...")
        resp = client.post(status_url, headers=headers, json=payload)
        print("Status request response:", resp.status_code, resp.text)

if __name__ == "__main__":
    check_status_direct()
