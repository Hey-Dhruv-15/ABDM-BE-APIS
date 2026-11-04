"""
YAML-driven mapping engine for transformations.
"""
import yaml
from typing import Any, Dict, Optional
from app.core.canonical.models import CanonicalMessage
from app.logging.logger import get_logger

logger = get_logger(__name__)

class MappingEngine:
    """
    Engine that performs transformations based on YAML mapping definitions.
    """

    def __init__(self, mapping_def: Dict[str, Any]):
        self.mapping_def = mapping_def

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "MappingEngine":
        """Initialize the engine from a YAML string."""
        mapping_def = yaml.safe_load(yaml_content)
        return cls(mapping_def)

    def transform(self, message: CanonicalMessage) -> Dict[str, Any]:
        """
        Apply the mapping definition to a CanonicalMessage.
        """
        result = {}
        message_dict = message.model_dump()

        for target_path, source_path in self.mapping_def.items():
            value = self._get_value_by_path(message_dict, source_path)
            if value is not None:
                self._set_value_by_path(result, target_path, value)

        return result

    def _get_value_by_path(self, data: Dict[str, Any], path: str) -> Any:
        """Helper to get nested value using dot notation."""
        keys = path.split('.')
        curr = data
        for key in keys:
            if isinstance(curr, dict) and key in curr:
                curr = curr[key]
            else:
                return None
        return curr

    def _set_value_by_path(self, data: Dict[str, Any], path: str, value: Any) -> None:
        """Helper to set nested value using dot notation."""
        keys = path.split('.')
        curr = data
        for i, key in enumerate(keys[:-1]):
            if key not in curr:
                curr[key] = {}
            curr = curr[key]
        curr[keys[-1]] = value
