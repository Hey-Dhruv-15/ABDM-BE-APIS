import asyncio
import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv()

from app.services.sms_service import send_sms_otp

async def test():
    print("Sending live test SMS via Twilio...")
    res = await send_sms_otp("7019950521", "849201", patient_name="Roshan S")
    print(f"Send SMS Result: {res}")

if __name__ == "__main__":
    asyncio.run(test())
