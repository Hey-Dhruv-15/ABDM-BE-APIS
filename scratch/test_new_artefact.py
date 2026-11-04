import httpx
import json

resp = httpx.post("http://202.21.38.161:8005/api/v1/health-records/fetch-by-consent", json={
    "consentArtifactId": "4ed8be54-5b18-4003-83bf-b90fa277bab4"
}, timeout=30.0)

data = resp.json()
print("Status:", resp.status_code)
print("Patient ID:", data.get("patientId"))
print("Records count:", data.get("recordsCount"))
print(json.dumps(data, indent=2)[:500])
