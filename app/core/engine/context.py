"""
Execution context.
Carries request-scoped details through the pipeline.
"""
import uuid
from typing import Optional
from pydantic import BaseModel, Field

from app.core.exceptions import ConfigurationError


class RequestContext(BaseModel):
    """
    Context passed continuously through the processing pipeline. 
    It holds tracking identities and configuration routing info.
    """
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    integration_id: str
    client_ip: str
    region: str | None = None
    health_network: str | None = None
    
    # Placeholders for the dynamically loaded components needed by the engine
    integration_config: dict = Field(default_factory=dict)

    class Config:
        arbitrary_types_allowed = True

    def get_config_value(self, key: str, default: Optional[str] = None) -> str:
        """Safely fetch values from the active integration config."""
        if not self.integration_config:
            raise ConfigurationError(f"Integration config not loaded for {self.integration_id}")
        return self.integration_config.get(key, default)
