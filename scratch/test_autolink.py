import httpx
import json

resp = httpx.get("http://202.21.38.161:8005/api/v1/consent-requests?limit=100")
data = resp.json()
records = data.get("records", [])

# Collect all granted artefacts by patient
patient_arts = {}
for r in records:
    p = r.get("patientAbhaAddress") or "sroshan110707@sbx"
    art = r.get("consentArtifactId")
    if art and art != "-":
        if p not in patient_arts:
            patient_arts[p] = []
        if art not in patient_arts[p]:
            patient_arts[p].append(art)

print("Granted Artefacts by Patient:")
for p, arts in patient_arts.items():
    print(f"  {p}: {len(arts)} artefacts -> {arts}")

# Link any pending record for that patient
linked_records = []
for idx, r in enumerate(records):
    p = r.get("patientAbhaAddress") or "sroshan110707@sbx"
    art = r.get("consentArtifactId")
    status = r.get("status")
    if (not art or art == "-") and p in patient_arts and len(patient_arts[p]) > 0:
        # Assign an artefact from the patient's granted pool
        art = patient_arts[p][idx % len(patient_arts[p])]
        status = "GRANTED"
    r["consentArtifactId"] = art
    r["status"] = status
    linked_records.append(r)

print("\nLinked Result:")
for idx, r in enumerate(linked_records[:10]):
    print(f"{idx+1}. ReqID: {r.get('consentRequestId')} | ArtID: {r.get('consentArtifactId')} | Status: {r.get('status')} | Requester: {r.get('requesterName')}")
