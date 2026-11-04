"""
Base transformer abstraction.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from app.core.canonical.models import CanonicalMessage

class BaseTransformer(ABC):
    """
    Abstract base class for all transformers.
    Transformers take a CanonicalMessage and convert it to a target format.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    @abstractmethod
    async def transform(self, message: CanonicalMessage) -> Any:
        """
        Transform the canonical message to the target format.
        
        Args:
            message: The canonical internal message representation.
            
        Returns:
            The transformed message in the target format (dict, string, etc.)
        """
        pass

    @property
    @abstractmethod
    def target_format(self) -> str:
        """The target format this transformer produces (e.g., 'fhir', 'hl7')."""
        pass
