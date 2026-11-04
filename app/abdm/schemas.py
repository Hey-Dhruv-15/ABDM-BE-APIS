"""Pydantic models used by the ABDM gateway client."""
from pydantic import BaseModel, Field


class SessionTokenResponse(BaseModel):
    """Response model for ABDM session token generation."""

    access_token: str = Field(alias="accessToken")
    expires_in: int = Field(alias="expiresIn")
    token_type: str = Field(default="Bearer", alias="tokenType")


class ConsentPayload(BaseModel):
    """Consent payload for ABHA enrollment APIs."""

    code: str = "abha-enrollment"
    version: str = "1.4"
