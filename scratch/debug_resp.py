import httpx
resp = httpx.get("http://202.21.38.161:8005/api/v1/consent-requests?limit=100", headers={"X-Region": "india"})
print("Status Code:", resp.status_code)
data = resp.json()
print("Total records:", data.get("total"))
for idx, r in enumerate(data.get("records", [])):
    print(f"{idx+1}. ReqID: {r.get('consentRequestId')} | ArtID: {r.get('consentArtifactId')} | Status: {r.get('status')} | Requester: {r.get('requesterName')}")
