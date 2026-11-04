"""Pydantic models used by the NABIDH client."""
from pydantic import BaseModel, Field


class NabidhTokenResponse(BaseModel):
    """Response model for NABIDH OAuth token generation."""

    access_token: str = Field(alias="access_token")
    token_type: str = Field(default="Bearer", alias="token_type")
    expires_in: int = Field(default=3600, alias="expires_in")

