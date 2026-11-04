import httpx
import json

resp = httpx.get("http://202.21.38.161:8005/api/v1/consent-requests?limit=100")
data = resp.json()
records = data.get("records", [])

# Let's test smart deduplication
dedup_dict = {}
art_map = {}

for item in records:
    c_req = item.get("consentRequestId")
    c_art = item.get("consentArtifactId")
    if c_req == "c1":
        continue
        
    # Check if we have seen this artifact or req id
    target_key = None
    if c_art and c_art != "-" and c_art in art_map:
        target_key = art_map[c_art]
    elif c_req in dedup_dict:
        target_key = c_req
    elif c_art and c_art != "-" and c_req == c_art:
        # This was an artifact key row
        continue

    if target_key:
        existing = dedup_dict[target_key]
        if (not existing.get("consentArtifactId") or existing.get("consentArtifactId") == "-") and c_art != "-":
            existing["consentArtifactId"] = c_art
        if item.get("status") == "GRANTED":
            existing["status"] = "GRANTED"
        if existing.get("patientName") == "sroshan110707" and item.get("patientName") != "sroshan110707":
            existing["patientName"] = item.get("patientName")
    else:
        dedup_dict[c_req] = dict(item)
        if c_art and c_art != "-":
            art_map[c_art] = c_req

print(f"Original: {len(records)} -> Deduplicated: {len(dedup_dict)}")
for idx, (k, v) in enumerate(dedup_dict.items()):
    print(f"{idx+1}. ReqID: {v.get('consentRequestId')} | ArtID: {v.get('consentArtifactId')} | Status: {v.get('status')} | Requester: {v.get('requesterName')}")
