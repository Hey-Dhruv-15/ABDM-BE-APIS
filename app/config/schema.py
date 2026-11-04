"""
Configuration schema for gateway integrations.
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class RetryConfig(BaseModel):
    """Configuration for retry logic."""
    max_retries: int = Field(default=3, ge=0)
    backoff_factor: float = Field(default=2.0, ge=1.0)
    max_delay: float = Field(default=30.0)
    retry_on_status: List[int] = Field(default_factory=lambda: [500, 502, 503, 504])

class AuthConfig(BaseModel):
    """Configuration for authentication."""
    type: str = Field(..., description="Auth type: none, api_key, oauth2, mtls, hmac")
    config: Dict[str, Any] = Field(default_factory=dict)

class IntegrationConfig(BaseModel):
    """
    Schema for an individual integration pipeline.
    """
    name: str = Field(..., description="Unique name for the integration")
    description: Optional[str] = None
    
    # Pipeline components
    parser: str = Field(..., description="Parser type (e.g., 'fhir', 'hl7')")
    transformer: str = Field(..., description="Transformer type (e.g., 'fhir', 'hl7')")
    producer: str = Field(..., description="Producer type (e.g., 'http', 'mllp')")
    
    # Security
    auth: AuthConfig = Field(default_factory=lambda: AuthConfig(type="none"))
    
    # Reliable Delivery
    retries: RetryConfig = Field(default_factory=RetryConfig)
    
    # Target settings (passed to producer)
    target_config: Dict[str, Any] = Field(default_factory=dict)
    
    # Specific component settings
    parser_config: Dict[str, Any] = Field(default_factory=dict)
    transformer_config: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"
