"""
API Key authentication handler.
"""

from typing import Any

from app.core.constants import HEADER_API_KEY
from app.core.exceptions import AuthenticationError
from app.logging.logger import get_logger

logger = get_logger(__name__)


class APIKeyAuth:
    """API Key authentication handler."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._valid_keys: set[str] = set(self._config.get("valid_keys", []))
        self._header_name = self._config.get("header_name") or self._config.get("header", HEADER_API_KEY)

    def add_key(self, key: str) -> None:
        """Add a valid API key."""
        self._valid_keys.add(key)

    def remove_key(self, key: str) -> None:
        """Remove an API key."""
        self._valid_keys.discard(key)

    async def authenticate(self, request: Any) -> bool:
        """
        Authenticate a request using API key.

        Args:
            request: The incoming request.

        Returns:
            True if authentication succeeds.

        Raises:
            AuthenticationError: If authentication fails.
        """
        # Extract API key from header
        api_key = self._get_api_key(request)

        if not api_key:
            logger.warning("API key missing")
            raise AuthenticationError("API key is required")

        if api_key not in self._valid_keys:
            logger.warning("Invalid API key")
            raise AuthenticationError("Invalid API key")

        return True

    def _get_api_key(self, request: Any) -> str | None:
        """Extract API key from request."""
        # Try to get from headers
        if hasattr(request, "headers"):
            return request.headers.get(self._header_name)
        return None


class APIKeyValidator:
    """Validates API keys."""

    @staticmethod
    def validate_format(key: str) -> bool:
        """Validate API key format."""
        if not key or len(key) < 16:
            return False
        return True
