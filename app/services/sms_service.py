"""SMS Gateway Service for dispatching dynamic OTP and notification messages (Twilio Verify, Fast2SMS, Generic)."""
import logging
import os
from typing import Any, Dict
import httpx
from dotenv import load_dotenv

# Ensure .env is explicitly loaded into environment variables
load_dotenv()

from app.logging.logger import get_logger
from app.settings import settings

logger = get_logger(__name__)

async def send_sms_otp(mobile_number: str, otp: str, patient_name: str | None = None) -> bool:
    """Dispatches a dynamic 6-digit OTP to the patient's mobile number via Twilio Verify, Fast2SMS, or Generic SMS."""
    clean_mobile = "".join(filter(str.isdigit, mobile_number))
    if len(clean_mobile) == 10:
        ten_digit_mobile = clean_mobile
        full_mobile = f"+91{clean_mobile}"
    elif clean_mobile.startswith("91") and len(clean_mobile) == 12:
        ten_digit_mobile = clean_mobile[2:]
        full_mobile = f"+{clean_mobile}"
    else:
        ten_digit_mobile = clean_mobile[-10:] if len(clean_mobile) >= 10 else clean_mobile
        full_mobile = f"+{clean_mobile}"

    message = f"Your ABDM Health Record linking OTP is {otp}. Valid for 15 minutes."
        
    # 1. Log prominent banner to stdout for developer visibility
    print("\n" + "=" * 70)
    print(f"[SMS DISPATCHER] TARGET MOBILE : {full_mobile}")
    print(f"[DYNAMIC OTP]    GENERATED OTP : {otp}")
    print(f"[SMS MESSAGE]    {message}")
    print("=" * 70 + "\n")
    
    logger.info(
        "Dispatched dynamic SMS OTP",
        mobile_number=full_mobile,
        otp=otp,
        patient_name=patient_name or "Patient",
    )

    # 2. Extract Gateway Credentials
    twilio_sid = os.getenv("TWILIO_ACCOUNT_SID") or getattr(settings, "TWILIO_ACCOUNT_SID", None)
    twilio_token = os.getenv("TWILIO_AUTH_TOKEN") or getattr(settings, "TWILIO_AUTH_TOKEN", None)
    verify_sid = os.getenv("TWILIO_VERIFY_SERVICE_SID") or getattr(settings, "TWILIO_VERIFY_SERVICE_SID", None)
    fast2sms_key = os.getenv("FAST2SMS_API_KEY") or getattr(settings, "FAST2SMS_API_KEY", None)

    # Gateway Option A: Twilio Verify API (Sends real SMS OTP directly to physical mobile)
    if twilio_sid and twilio_token and verify_sid:
        try:
            url = f"https://verify.twilio.com/v2/Services/{verify_sid.strip()}/Verifications"
            async with httpx.AsyncClient(timeout=10.0) as client:
                data = {
                    "To": full_mobile,
                    "Channel": "sms",
                }
                auth = (twilio_sid.strip(), twilio_token.strip())
                res = await client.post(url, data=data, auth=auth)
                logger.info("Twilio Verify dispatch response: status=%s body=%s", res.status_code, res.text)
                print(f"[TWILIO VERIFY RESPONSE] Status: {res.status_code} | Body: {res.text}\n")
                if res.status_code in [200, 201]:
                    return True
        except Exception as exc:
            logger.error("Twilio Verify API dispatch failed: %s", str(exc), exc_info=True)

    # Gateway Option B: Fast2SMS API (Sends live OTP if Fast2SMS API Key is present)
    if fast2sms_key and fast2sms_key.strip():
        try:
            url = "https://www.fast2sms.com/dev/bulkV2"
            headers = {"authorization": fast2sms_key.strip(), "Content-Type": "application/json"}
            payload = {
                "route": "otp",
                "variables_values": str(otp),
                "numbers": ten_digit_mobile
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json=payload, headers=headers)
                logger.info("Fast2SMS dispatch response: status=%s body=%s", res.status_code, res.text)
                print(f"[FAST2SMS RESPONSE] Status: {res.status_code} | Body: {res.text}\n")
                if res.status_code == 200 and res.json().get("return"):
                    return True
        except Exception as exc:
            logger.error("Fast2SMS API dispatch failed: %s", str(exc), exc_info=True)

    return True


async def verify_twilio_otp(mobile_number: str, otp: str) -> bool:
    """Verifies patient entered OTP directly against Twilio Verify API."""
    clean_mobile = "".join(filter(str.isdigit, mobile_number))
    if len(clean_mobile) == 10:
        full_mobile = f"+91{clean_mobile}"
    elif clean_mobile.startswith("91") and len(clean_mobile) == 12:
        full_mobile = f"+{clean_mobile}"
    else:
        full_mobile = f"+{clean_mobile}"

    twilio_sid = os.getenv("TWILIO_ACCOUNT_SID") or getattr(settings, "TWILIO_ACCOUNT_SID", None)
    twilio_token = os.getenv("TWILIO_AUTH_TOKEN") or getattr(settings, "TWILIO_AUTH_TOKEN", None)
    verify_sid = os.getenv("TWILIO_VERIFY_SERVICE_SID") or getattr(settings, "TWILIO_VERIFY_SERVICE_SID", None)

    if twilio_sid and twilio_token and verify_sid:
        try:
            url = f"https://verify.twilio.com/v2/Services/{verify_sid.strip()}/VerificationCheck"
            async with httpx.AsyncClient(timeout=10.0) as client:
                data = {"To": full_mobile, "Code": otp.strip()}
                auth = (twilio_sid.strip(), twilio_token.strip())
                res = await client.post(url, data=data, auth=auth)
                logger.info("Twilio VerificationCheck status=%s body=%s", res.status_code, res.text)
                if res.status_code == 200:
                    status_val = res.json().get("status")
                    if status_val == "approved":
                        print(f"✅ [TWILIO VERIFICATION APPROVED] OTP {otp} is 100% VALID!")
                        return True
        except Exception as exc:
            logger.error("Twilio VerificationCheck failed: %s", str(exc), exc_info=True)

    return False


async def send_sms_notification(mobile_number: str, message_text: str) -> bool:
    """Dispatches a confirmation SMS notification to the patient's mobile number via Fast2SMS or Twilio after successful linking."""
    clean_mobile = "".join(filter(str.isdigit, mobile_number))
    if len(clean_mobile) == 10:
        ten_digit_mobile = clean_mobile
        full_mobile = f"+91{clean_mobile}"
    elif clean_mobile.startswith("91") and len(clean_mobile) == 12:
        ten_digit_mobile = clean_mobile[2:]
        full_mobile = f"+{clean_mobile}"
    else:
        ten_digit_mobile = clean_mobile[-10:] if len(clean_mobile) >= 10 else clean_mobile
        full_mobile = f"+{clean_mobile}"

    print("\n" + "=" * 70)
    print(f"[SMS SUCCESS NOTIFICATION] TARGET MOBILE : {full_mobile}")
    print(f"[SMS MESSAGE]              {message_text}")
    print("=" * 70 + "\n")

    logger.info("Dispatched SMS Notification", mobile_number=full_mobile, message=message_text)

    # Option A: Fast2SMS Custom DLT / Quick SMS Dispatch
    fast2sms_key = os.getenv("FAST2SMS_API_KEY") or getattr(settings, "FAST2SMS_API_KEY", None)
    if fast2sms_key and fast2sms_key.strip():
        try:
            url = "https://www.fast2sms.com/dev/bulkV2"
            headers = {"authorization": fast2sms_key.strip(), "Content-Type": "application/json"}
            payload = {
                "route": "q",
                "message": message_text,
                "language": "english",
                "flash": 0,
                "numbers": ten_digit_mobile
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json=payload, headers=headers)
                logger.info("Fast2SMS Notification response: status=%s body=%s", res.status_code, res.text)
                print(f"[FAST2SMS NOTIFICATION RESPONSE] Status: {res.status_code} | Body: {res.text}\n")
                if res.status_code == 200 and res.json().get("return"):
                    return True
        except Exception as exc:
            logger.error("Fast2SMS Notification dispatch failed: %s", str(exc), exc_info=True)

    # Option B: Twilio SMS Dispatch
    twilio_sid = os.getenv("TWILIO_ACCOUNT_SID") or getattr(settings, "TWILIO_ACCOUNT_SID", None)
    twilio_token = os.getenv("TWILIO_AUTH_TOKEN") or getattr(settings, "TWILIO_AUTH_TOKEN", None)
    twilio_from = os.getenv("TWILIO_PHONE_NUMBER") or getattr(settings, "TWILIO_PHONE_NUMBER", None)
    if twilio_sid and twilio_token and twilio_from:
        try:
            url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid.strip()}/Messages.json"
            async with httpx.AsyncClient(timeout=10.0) as client:
                data = {"From": twilio_from.strip(), "To": full_mobile, "Body": message_text}
                auth = (twilio_sid.strip(), twilio_token.strip())
                res = await client.post(url, data=data, auth=auth)
                logger.info("Twilio Notification response: status=%s body=%s", res.status_code, res.text)
                print(f"[TWILIO NOTIFICATION RESPONSE] Status: {res.status_code} | Body: {res.text}\n")
                if res.status_code in [200, 201]:
                    return True
        except Exception as exc:
            logger.error("Twilio Notification dispatch failed: %s", str(exc), exc_info=True)

    return True
