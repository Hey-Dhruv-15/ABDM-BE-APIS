"""
Base producer abstraction.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class BaseProducer(ABC):
    """
    Abstract base class for all outbound producers.
    Producers take transformed data and send it to a destination.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    @abstractmethod
    async def send(self, data: Any, metadata: Optional[Dict[str, Any]] = None) -> Any:
        """
        Send the data to the target destination.

        Args:
            data: The transformed message data to send.
            metadata: Optional metadata for the transmission.

        Returns:
            Success indicator or response from destination.
        """
        pass

    @abstractmethod
    async def ping(self) -> bool:
        """Check if the destination is reachable."""
        pass
