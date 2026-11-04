"""
Factory for creating producer instances based on configuration.
"""
from typing import Any, Dict, Optional, Type
from app.producers.base import BaseProducer
from app.producers.http_sender import HTTPSender
from app.producers.mllp_sender import MLLPSender
from app.core.exceptions import ConfigurationError

class ProducerFactory:
    """
    Factory class to dynamically instantiate producers.
    """
    
    _registry: Dict[str, Type[BaseProducer]] = {
        "http": HTTPSender,
        "https": HTTPSender,
        "mllp": MLLPSender
    }

    @classmethod
    def create(cls, producer_type: str, config: Optional[Dict[str, Any]] = None) -> BaseProducer:
        """
        Create a producer instance based on type and configuration.
        
        Args:
            producer_type: The type of producer ('http', 'mllp', etc.)
            config: Configuration dictionary for the producer.
            
        Returns:
            An instance of a BaseProducer subclass.
            
        Raises:
            ConfigurationError: If the producer type is unknown.
        """
        producer_cls = cls._registry.get(producer_type.lower())
        if not producer_cls:
            raise ConfigurationError(
                f"Unknown producer type: {producer_type}. "
                f"Available types: {list(cls._registry.keys())}"
            )
            
        return producer_cls(config)

    @classmethod
    def register(cls, name: str, producer_cls: Type[BaseProducer]) -> None:
        """Register a new producer type."""
        cls._registry[name.lower()] = producer_cls
