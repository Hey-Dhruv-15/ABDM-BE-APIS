import asyncio
from app.abdm.auth import ABDMAuthService
from app.abdm.client import ABDMGatewayClient
from app.settings import settings

async def test():
    auth = ABDMAuthService()
    client = ABDMGatewayClient(auth)
    
    payload = {
        "transactionId": "6fc78239-90c1-4963-8334-1e0661d63cfc",
        "link": {
            "referenceNumber": "LINK-REF-6FC78239",
            "authenticationType": "MEDIATE",
            "meta": {
                "communicationMedium": "MOBILE",
                "communicationHint": "OTP",
                "communicationExpiry": "2026-12-30T12:00:00.000Z"
            }
        },
        "response": {"requestId": "e4535f8f-e24c-4922-98d3-57fdbb62d669"}
    }
    
    extra_headers = {
        "REQUEST-ID": "e4535f8f-e24c-4922-98d3-57fdbb62d669",
        "TIMESTAMP": "2026-08-12T07:06:15.118Z",
        "X-CM-ID": "sbx",
        "X-Region": "india",
        "X-Integration": "test-relay",
        "X-HIP-ID": "IN2910002345",
    }
    
    print("Posting on-init to ABDM Gateway...")
    try:
        res = await client.post(
            settings.ABDM_M2_CARE_CONTEXTS_LINK_PATH,
            payload,
            participant_id="IN2910002345",
            participant_type="HIP",
            extra_headers=extra_headers,
        )
        print("Response from Gateway:", res)
    except Exception as exc:
        print("Error from Gateway:", exc)

if __name__ == "__main__":
    asyncio.run(test())
