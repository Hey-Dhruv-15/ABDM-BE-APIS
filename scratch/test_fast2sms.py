import asyncio
import httpx

api_key = "placeholder-api-key"

async def test_fast2sms():
    url = "https://www.fast2sms.com/dev/bulkV2"
    headers = {
        "authorization": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "route": "otp",
        "variables_values": "730844",
        "numbers": "7019950521"
    }
    async with httpx.AsyncClient() as client:
        res = await client.post(url, json=payload, headers=headers)
        print("Fast2SMS Status:", res.status_code)
        print("Fast2SMS Response:", res.text)

if __name__ == "__main__":
    asyncio.run(test_fast2sms())
