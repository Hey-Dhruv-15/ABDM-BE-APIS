"""
JSON utilities for safe serialization and data masking.
"""
import json
from typing import Any, Dict, List, Optional
from datetime import datetime
from app.logging.logger import get_logger

logger = get_logger(__name__)

class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for handling types like datetime."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def safe_json_loads(data: str, default: Any = None) -> Any:
    """Safe JSON parsing with error handling."""
    if not data:
        return default
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse JSON", error=str(e))
        return default

def safe_json_dumps(data: Any, pretty: bool = False) -> str:
    """Safe JSON serialization with custom encoding."""
    try:
        indent = 2 if pretty else None
        return json.dumps(data, cls=JSONEncoder, indent=indent)
    except (TypeError, ValueError) as e:
        logger.error("Failed to serialize to JSON", error=str(e))
        return "{}"

def mask_sensitive_fields(data: Dict[str, Any], sensitive_keys: List[str] = None) -> Dict[str, Any]:
    """
    Recursively mask sensitive fields in a dictionary.
    """
    if sensitive_keys is None:
        sensitive_keys = ["password", "token", "secret", "api_key", "authorization"]
    
    masked_data = data.copy()
    for key, value in masked_data.items():
        if any(sk in key.lower() for sk in sensitive_keys):
            masked_data[key] = "********"
        elif isinstance(value, dict):
            masked_data[key] = mask_sensitive_fields(value, sensitive_keys)
        elif isinstance(value, list):
            masked_data[key] = [
                mask_sensitive_fields(v, sensitive_keys) if isinstance(v, dict) else v 
                for v in value
            ]
    return masked_data
