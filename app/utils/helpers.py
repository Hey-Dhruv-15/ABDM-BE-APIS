"""
General helper functions for the gateway.
"""
import uuid
import socket
from typing import Any, Dict

def generate_id() -> str:
    """Generate a unique UUID v4 string."""
    return str(uuid.uuid4())

def get_hostname() -> str:
    """Get the current system hostname."""
    return socket.gethostname()

def deep_merge(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two dictionaries.
    """
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def is_valid_uuid(val: str) -> bool:
    """Check if a string is a valid UUID."""
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False
