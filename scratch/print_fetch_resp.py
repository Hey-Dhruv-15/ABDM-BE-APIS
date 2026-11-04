import httpx
import json

resp = httpx.post("http://202.21.38.161:8005/api/v1/health-records/fetch-by-consent", json={
    "consentArtifactId": "00603cdf-844c-4add-b58c-e5af93d0cc79"
}, timeout=30.0)
print("Status Code:", resp.status_code)
print(json.dumps(resp.json(), indent=2)[:1000])
