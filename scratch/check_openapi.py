import httpx
import json

resp = httpx.get("http://202.21.38.161:8005/api/v1/openapi.json")
print("OpenAPI Status:", resp.status_code)
if resp.status_code == 200:
    spec = resp.json()
    paths = list(spec.get("paths", {}).keys())
    print("Total Endpoints in OpenAPI:", len(paths))
    
    target_endpoints = [
        "/api/v1/consent-requests",
        "/api/v1/health-records/fetch-by-consent",
        "/api/v1/m3/links/context/notify",
        "/api/v1/health-records",
        "/api/v1/m3/patients/profile/share"
    ]
    for ep in target_endpoints:
        if ep in paths:
            print(f"[FOUND] {ep} is LIVE in Swagger Docs ({list(spec['paths'][ep].keys())})")
        else:
            print(f"[MISSING] {ep} is MISSING from Swagger Docs")
