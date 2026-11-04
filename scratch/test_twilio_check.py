import asyncio
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

sid = os.getenv("TWILIO_ACCOUNT_SID")
token = os.getenv("TWILIO_AUTH_TOKEN")
verify_sid = os.getenv("TWILIO_VERIFY_SERVICE_SID")

async def test_check(otp_code: str):
    async with httpx.AsyncClient() as client:
        url = f"https://verify.twilio.com/v2/Services/{verify_sid}/VerificationCheck"
        data = {
            "To": "+917019950521",
            "Code": otp_code
        }
        res = await client.post(url, data=data, auth=(sid, token))
        print("Check Status:", res.status_code)
        print("Check Response:", res.text)
        if res.status_code == 200:
            status = res.json().get("status")
            print(f"Verification Result: {status}")

if __name__ == "__main__":
    asyncio.run(test_check("123456"))
