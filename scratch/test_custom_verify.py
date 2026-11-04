import asyncio
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

sid = os.getenv("TWILIO_ACCOUNT_SID")
token = os.getenv("TWILIO_AUTH_TOKEN")
verify_sid = os.getenv("TWILIO_VERIFY_SERVICE_SID")

async def test():
    async with httpx.AsyncClient() as client:
        # Enable custom code on Twilio Verify Service
        update_url = f"https://verify.twilio.com/v2/Services/{verify_sid}"
        up_res = await client.post(update_url, data={"CustomCodeEnabled": "true"}, auth=(sid, token))
        print("Enable Custom Code Status:", up_res.status_code)
        print("Enable Custom Code Body:", up_res.text)

        # Send custom OTP code via Twilio Verify API
        send_url = f"https://verify.twilio.com/v2/Services/{verify_sid}/Verifications"
        data = {
            "To": "+917019950521",
            "Channel": "sms",
            "CustomCode": "730844"
        }
        res = await client.post(send_url, data=data, auth=(sid, token))
        print("Send Custom OTP Status:", res.status_code)
        print("Send Custom OTP Response:", res.text)

if __name__ == "__main__":
    asyncio.run(test())
