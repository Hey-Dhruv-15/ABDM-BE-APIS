import asyncio
import httpx

sid = "placeholder-account-sid"
token = "placeholder-auth-token"

async def test():
    async with httpx.AsyncClient() as client:
        # Create a Twilio Verify Service
        url = "https://verify.twilio.com/v2/Services"
        res = await client.post(url, data={"FriendlyName": "ABDM Health Link"}, auth=(sid, token))
        print("Create Verify Service Status:", res.status_code)
        print("Create Verify Service Response:", res.text)
        
        if res.status_code in [200, 201]:
            verify_sid = res.json()["sid"]
            print(f"Created Verify Service SID: {verify_sid}")
            
            # Send SMS via Twilio Verify
            send_url = f"https://verify.twilio.com/v2/Services/{verify_sid}/Verifications"
            send_res = await client.post(send_url, data={"To": "+917019950521", "Channel": "sms"}, auth=(sid, token))
            print("Send Verify SMS Status:", send_res.status_code)
            print("Send Verify SMS Response:", send_res.text)

if __name__ == "__main__":
    asyncio.run(test())
