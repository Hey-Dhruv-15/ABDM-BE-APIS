"""
Time utilities for consistent timestamp handling.
"""
from datetime import datetime, timezone

def get_utc_now() -> datetime:
    """Get the current time in UTC with timezone info."""
    return datetime.now(timezone.utc)

def format_iso(dt: datetime) -> str:
    """Format datetime as ISO 8601 string."""
    return dt.isoformat()

def parse_iso(iso_str: str) -> datetime:
    """Parse ISO 8601 string to datetime."""
    return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))

def get_timestamp_ms() -> int:
    """Get current unix timestamp in milliseconds."""
    return int(datetime.now(timezone.utc).timestamp() * 1000)
