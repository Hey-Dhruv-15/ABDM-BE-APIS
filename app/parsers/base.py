"""
Base parser interface.
Defines the standard contract for translating raw incoming payloads
into the internal canonical model.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Union

from app.core.canonical.models import CanonicalMessage


class BaseParser(ABC):
    """Abstract base class for all message parsers."""

    @abstractmethod
    async def parse(self, raw_payload: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Parses the raw incoming payload into a workable Python dictionary.
        Raises ParsingError if format is invalid.
        """
        pass

    @abstractmethod
    def to_canonical(self, parsed_data: Dict[str, Any]) -> CanonicalMessage:
        """
        Transforms the format-specific parsed dictionary into the universal CanonicalMessage.
        """
        pass
