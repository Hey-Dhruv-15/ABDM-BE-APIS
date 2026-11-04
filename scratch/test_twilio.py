import asyncio
import os
import sys
import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sid = "placeholder-account-sid"
token = "placeholder-auth-token"

async def test():
    async with httpx.AsyncClient() as client:
        # Check incoming phone numbers in account
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers.json"
        res = await client.get(url, auth=(sid, token))
        print(f"Incoming Numbers Status: {res.status_code}")
        print(f"Incoming Numbers Body: {res.text}")

if __name__ == "__main__":
    asyncio.run(test())
