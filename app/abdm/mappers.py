"""Canonical-to-ABDM payload mappers for ABHA flows."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.abdm.canonical import (
    AbhaV3AuthDataCanonical,
    AbhaV3EnrollByAadhaarRequestCanonical,
    AbhaV3EnrollRequestOtpCanonical,
    AbhaV3LoginRequestOtpCanonical,
    AbhaV3LoginVerifyRequestCanonical,
    AbhaV3OtpPayloadCanonical,
    AbhaV3SearchRequestCanonical,
    EncryptableField,
)
from app.abdm.crypto import encrypt_abha_value, encrypt_otp
from app.abdm.rsa import normalize_indian_mobile


def requires_encryption(payload: BaseModel | dict | list | Any) -> bool:
    """Detect whether a payload contains any encryptable fields."""
    if isinstance(payload, EncryptableField):
        return bool(payload.encrypt)
    if isinstance(payload, BaseModel):
        return any(requires_encryption(getattr(payload, name)) for name in payload.model_fields)
    if isinstance(payload, dict):
        return any(requires_encryption(value) for value in payload.values())
    if isinstance(payload, list):
        return any(requires_encryption(value) for value in payload)
    return False


def _encrypt_field(field: EncryptableField, public_key_b64: str) -> str:
    if field.encrypt:
        return encrypt_abha_value(field.value, public_key_b64)
    return field.value


def map_abha_v3_search(payload: AbhaV3SearchRequestCanonical, public_key_b64: str | None) -> dict:
    mobile = _encrypt_field(payload.mobile, public_key_b64) if public_key_b64 else payload.mobile.value
    return {
        "scope": payload.scope,
        "mobile": mobile,
    }


def map_abha_v3_login_request_otp(
    payload: AbhaV3LoginRequestOtpCanonical, public_key_b64: str | None
) -> dict:
    login_id = _encrypt_field(payload.loginId, public_key_b64) if public_key_b64 else payload.loginId.value
    return {
        "scope": payload.scope,
        "loginHint": payload.loginHint,
        "loginId": login_id,
        "otpSystem": payload.otpSystem,
        "txnId": payload.txnId,
    }


def _map_otp_payload(payload: AbhaV3OtpPayloadCanonical, public_key_b64: str | None) -> dict:
    otp_value = _encrypt_field(payload.otpValue, public_key_b64) if public_key_b64 else payload.otpValue.value
    mapped = {
        "txnId": payload.txnId,
        "otpValue": otp_value,
    }
    if payload.mobile:
        mapped["mobile"] = (
            _encrypt_field(payload.mobile, public_key_b64) if public_key_b64 else payload.mobile.value
        )
    return mapped


def _map_auth_data(payload: AbhaV3AuthDataCanonical, public_key_b64: str | None) -> dict:
    mapped = {"authMethods": payload.authMethods}
    if payload.otp:
        mapped["otp"] = _map_otp_payload(payload.otp, public_key_b64)
    return mapped


def map_abha_v3_login_verify(payload: AbhaV3LoginVerifyRequestCanonical, public_key_b64: str | None) -> dict:
    return {
        "scope": payload.scope,
        "authData": _map_auth_data(payload.authData, public_key_b64),
    }


def map_abha_v3_enroll_request_otp(
    payload: AbhaV3EnrollRequestOtpCanonical, public_key_b64: str | None
) -> dict:
    login_id = _encrypt_field(payload.loginId, public_key_b64) if public_key_b64 else payload.loginId.value
    return {
        "txnId": payload.txnId,
        "scope": payload.scope,
        "loginHint": payload.loginHint,
        "loginId": login_id,
        "otpSystem": payload.otpSystem,
    }


def map_abha_v3_enroll_by_aadhaar(
    payload: AbhaV3EnrollByAadhaarRequestCanonical, public_key_b64: str | None
) -> dict:
    auth_data = {"authMethods": payload.authData.authMethods}
    if payload.authData.otp:
        otp = payload.authData.otp
        otp_value = (
            encrypt_otp(otp.otpValue.value, public_key_b64)
            if otp.otpValue.encrypt and public_key_b64
            else otp.otpValue.value
        )
        mapped_otp = {
            "txnId": otp.txnId,
            "otpValue": otp_value,
        }
        if otp.mobile:
            mapped_otp["mobile"] = normalize_indian_mobile(otp.mobile.value)
        auth_data["otp"] = mapped_otp
    mapped = {"authData": auth_data}
    if payload.consent is not None:
        mapped["consent"] = payload.consent.model_dump(exclude_none=True)
    return mapped


def redact_encryptable(payload: BaseModel | dict | list | Any) -> Any:
    """Redact encryptable values for safe logging."""
    if isinstance(payload, EncryptableField):
        return {"value": "***masked***", "encrypt": payload.encrypt}
    if isinstance(payload, BaseModel):
        return {
            name: redact_encryptable(getattr(payload, name))
            for name in payload.model_fields
        }
    if isinstance(payload, dict):
        return {key: redact_encryptable(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redact_encryptable(value) for value in payload]
    return payload
