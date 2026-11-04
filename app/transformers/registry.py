"""
Transformer registry for looking up transformation logic by target format.
"""
from typing import Dict, Type, Optional
from app.transformers.base import BaseTransformer
from app.core.exceptions import ConfigurationError

class TransformerRegistry:
    """Registry for managing transformer implementations."""
    
    _transformers: Dict[str, Type[BaseTransformer]] = {}

    @classmethod
    def register(cls, target_format: str):
        """Decorator to register a transformer class."""
        def decorator(transformer_cls: Type[BaseTransformer]):
            cls._transformers[target_format.lower()] = transformer_cls
            return transformer_cls
        return decorator

    @classmethod
    def get_transformer_class(cls, target_format: str) -> Type[BaseTransformer]:
        """Get the transformer class for a given target format."""
        transformer_cls = cls._transformers.get(target_format.lower())
        if not transformer_cls:
            raise ConfigurationError(f"No transformer registered for format: {target_format}")
        return transformer_cls

    @classmethod
    def list_formats(self) -> list[str]:
        """List all registered target formats."""
        return list(self._transformers.keys())
