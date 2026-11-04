import asyncio
import httpx

sid = "placeholder-account-sid"
token = "placeholder-auth-token"

async def test():
    async with httpx.AsyncClient() as client:
        # Search available local numbers in US
        search_url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/AvailablePhoneNumbers/US/Local.json"
        res = await client.get(search_url, auth=(sid, token))
        print("Search status:", res.status_code)
        data = res.json()
        avail = data.get("available_phone_numbers", [])
        if avail:
            num = avail[0]["phone_number"]
            print(f"Found available number: {num}")
            # Purchase number with trial credits
            buy_url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers.json"
            buy_res = await client.post(buy_url, data={"PhoneNumber": num}, auth=(sid, token))
            print("Buy status:", buy_res.status_code)
            print("Buy response:", buy_res.text)

if __name__ == "__main__":
    asyncio.run(test())
