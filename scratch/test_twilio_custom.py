import asyncio
import os
import sys
import httpx
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv()

sid = os.getenv("TWILIO_ACCOUNT_SID")
token = os.getenv("TWILIO_AUTH_TOKEN")
twilio_from = os.getenv("TWILIO_PHONE_NUMBER")

async def test():
    print(f"SID: {sid}, From: {twilio_from}")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    async with httpx.AsyncClient() as client:
        # Test sending exact custom message via Twilio Programmable SMS
        data = {
            "From": twilio_from,
            "To": "+917019950521",
            "Body": "Your ABDM Health Record linking OTP is 730844. Valid for 15 minutes. - Agamin Hospital",
        }
        res = await client.post(url, data=data, auth=(sid, token))
        print(f"Status: {res.status_code}")
        print(f"Body: {res.text}")

if __name__ == "__main__":
    asyncio.run(test())
