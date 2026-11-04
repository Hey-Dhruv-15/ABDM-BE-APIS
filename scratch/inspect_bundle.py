import httpx
import json

resp = httpx.post("http://202.21.38.161:8005/api/v1/health-records/fetch-by-consent", json={
    "consentArtifactId": "00603cdf-844c-4add-b58c-e5af93d0cc79"
}, timeout=30.0)

data = resp.json()
print("Patient ID:", data.get("patientId"))
print("Records count:", data.get("recordsCount"))

for key, bundle in data.get("records", {}).items():
    print(f"\n--- Bundle: {key} ---")
    for entry in bundle.get("entry", []):
        res = entry.get("resource", {})
        res_type = res.get("resourceType")
        if res_type == "Patient":
            print("  Patient resource:", json.dumps(res, indent=4))
        elif res_type == "Practitioner":
            print("  Practitioner resource:", json.dumps(res, indent=4))
        elif res_type == "Composition":
            print(f"  Composition: {res.get('title')} | Type: {res.get('type')}")
