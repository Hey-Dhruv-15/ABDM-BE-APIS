import httpx
import json

def test_fetch_records():
    url = "http://202.21.38.161:8005/api/v1/health-records/fetch-by-consent"
    payload = {
        "consentArtifactId": "00603cdf-844c-4add-b58c-e5af93d0cc79",
        "hiTypes": ["Prescription", "DiagnosticReport", "OPConsultation", "DischargeSummary"]
    }
    print(f"Testing POST {url} with artefact {payload['consentArtifactId']} ...")
    try:
        resp = httpx.post(url, json=payload, timeout=30.0)
        print(f"Status Code: {resp.status_code}")
        data = resp.json()
        print("Response Summary:")
        print(f"Status: {data.get('status')}")
        print(f"Patient Name: {data.get('patientName')}")
        print(f"Patient ABHA Address: {data.get('patientAbhaAddress')}")
        print(f"Total Records: {data.get('totalRecords')}")
        for r in data.get("records", []):
            print(f"- Type: {r.get('hiType')} | CareContext: {r.get('careContextReference')} | Decrypted Bundle Entries: {len(r.get('decryptedData', {}).get('entry', []))}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_fetch_records()
