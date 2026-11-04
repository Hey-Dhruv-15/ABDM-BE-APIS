"""
Canonical model definition.
All incoming messages are converted to this neutral Pydantic model representation
before undergoing business logic and transformations.
"""
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime
import uuid

class ModelMetadata(BaseModel):
    """Metadata regarding the original message and processing trace."""
    source_system: str
    target_system: Optional[str] = None
    original_format: str
    message_type: str
    received_at: datetime = Field(default_factory=datetime.utcnow)
    version: str = "1.0"


class Identifier(BaseModel):
    """Standardized identifier structure."""
    system: str
    value: str
    type: Optional[str] = None


class CanonicalDemographics(BaseModel):
    """Standardized demographics representation."""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    dob: Optional[str] = None
    gender: Optional[str] = None


class CanonicalMessage(BaseModel):
    """
    The universal internal representation.
    Serves as the central hub for the parse -> normalize -> transform pipeline.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metadata: ModelMetadata
    identifiers: List[Identifier] = []
    demographics: Optional[CanonicalDemographics] = None
    
    # Flexible catch-all for clinical payloads (e.g., Observations, Encounters)
    # that haven't been strictly modeled yet.
    payload: Dict[str, Any] = Field(default_factory=dict)
