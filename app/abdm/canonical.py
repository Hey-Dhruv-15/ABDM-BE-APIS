"""Canonical request models for ABDM ABHA flows."""
from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict, Field

from app.abdm.schemas import ConsentPayload


class EncryptableField(BaseModel):
    """Represents a field that may require RSA encryption before outbound calls."""

    value: str = Field(examples=["123456789012"])
    encrypt: bool = Field(default=False)
    model_config = ConfigDict(extra="forbid")


class AbhaV3SearchRequestCanonical(BaseModel):
    """Canonical request for ABHA V3 search by mobile."""

    scope: List[str] = Field(min_length=1, examples=[["search-abha"]])
    mobile: EncryptableField
    model_config = ConfigDict(extra="forbid")


class AbhaV3LoginRequestOtpCanonical(BaseModel):
    """Canonical request for ABHA V3 login OTP request."""

    scope: List[str] = Field(min_length=1, examples=[["abha-login", "search-abha", "mobile-verify"]])
    loginHint: str = Field(examples=["index"])
    loginId: EncryptableField
    otpSystem: str = Field(examples=["abdm"])
    txnId: str = Field(examples=["transaction-id"])
    model_config = ConfigDict(extra="forbid")


class AbhaV3OtpPayloadCanonical(BaseModel):
    txnId: str = Field(examples=["transaction-id"])
    otpValue: EncryptableField
    mobile: EncryptableField | None = None
    model_config = ConfigDict(extra="forbid")


class AbhaV3AuthDataCanonical(BaseModel):
    authMethods: List[str] = Field(examples=[["otp"]])
    otp: AbhaV3OtpPayloadCanonical | None = None
    model_config = ConfigDict(extra="forbid")


class AbhaV3LoginVerifyRequestCanonical(BaseModel):
    """Canonical request for ABHA V3 login OTP verification."""

    scope: List[str] = Field(min_length=1, examples=[["abha-login", "mobile-verify"]])
    authData: AbhaV3AuthDataCanonical
    model_config = ConfigDict(extra="forbid")


class AbhaV3EnrollRequestOtpCanonical(BaseModel):
    """Canonical request for ABHA V3 Aadhaar enrollment OTP request."""

    txnId: str | None = Field(default=None, examples=[""])
    scope: List[str] = Field(min_length=1, examples=[["abha-enrol"]])
    loginHint: str = Field(examples=["aadhaar"])
    loginId: EncryptableField
    otpSystem: str = Field(examples=["aadhaar"])
    model_config = ConfigDict(extra="forbid")


class AbhaV3EnrollByAadhaarRequestCanonical(BaseModel):
    """Canonical request for ABHA V3 Aadhaar enrollment verification."""

    authData: AbhaV3AuthDataCanonical
    consent: ConsentPayload | None = None
    model_config = ConfigDict(extra="forbid")
