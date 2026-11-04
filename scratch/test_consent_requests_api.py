import httpx
import json

def test_consent_requests():
    url = "http://202.21.38.161:8005/api/v1/consent-requests?sync=true&page=1&limit=10"
    print(f"Testing GET {url} ...")
    try:
        resp = httpx.get(url, timeout=30.0)
        print(f"Status Code: {resp.status_code}")
        data = resp.json()
        print(json.dumps(data, indent=2))
        
        records = data.get("records", [])
        print(f"\nTotal Records returned: {len(records)}")
        for idx, rec in enumerate(records):
            print(f"[{idx+1}] RequestId: {rec.get('consentRequestId')} | Status: {rec.get('status')} | ArtefactId: {rec.get('consentArtifactId')} | Patient: {rec.get('patientAbhaAddress')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_consent_requests()
