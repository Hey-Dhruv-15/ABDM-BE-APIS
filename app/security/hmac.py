"""
HMAC authentication handler.
"""

import hmac
import time
from typing import Any

from app.core.constants import HEADER_HMAC_SIGNATURE, HEADER_HMAC_TIMESTAMP
from app.core.exceptions import AuthenticationError
from app.logging.logger import get_logger

logger = get_logger(__name__)


class HMACAuth:
    """HMAC-based authentication handler."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._secret_key = self._config.get("secret_key", "")
        self._timestamp_tolerance = self._config.get("timestamp_tolerance", 300)  # 5 minutes

    async def authenticate(self, request: Any) -> bool:
        """
        Authenticate a request using HMAC signature.

        Args:
            request: The incoming request.

        Returns:
            True if authentication succeeds.

        Raises:
            AuthenticationError: If authentication fails.
        """
        signature = self._get_signature(request)
        timestamp = self._get_timestamp(request)

        if not signature:
            logger.warning("HMAC signature missing")
            raise AuthenticationError("HMAC signature is required")

        if not timestamp:
            logger.warning("HMAC timestamp missing")
            raise AuthenticationError("HMAC timestamp is required")

        # Validate timestamp to prevent replay attacks
        try:
            request_time = int(timestamp)
            current_time = int(time.time())
            if abs(current_time - request_time) > self._timestamp_tolerance:
                logger.warning("HMAC timestamp out of tolerance")
                raise AuthenticationError("Request timestamp out of tolerance")
        except ValueError:
            logger.warning("Invalid HMAC timestamp format")
            raise AuthenticationError("Invalid timestamp format")

        # Verify signature
        expected_signature = self._compute_signature(request, timestamp)
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("HMAC signature mismatch")
            raise AuthenticationError("Invalid HMAC signature")

        return True

    def _get_signature(self, request: Any) -> str | None:
        """Extract HMAC signature from request."""
        if hasattr(request, "headers"):
            return request.headers.get(HEADER_HMAC_SIGNATURE)
        return None

    def _get_timestamp(self, request: Any) -> str | None:
        """Extract timestamp from request."""
        if hasattr(request, "headers"):
            return request.headers.get(HEADER_HMAC_TIMESTAMP)
        return None

    def _compute_signature(self, request: Any, timestamp: str) -> str:
        """Compute expected HMAC signature."""
        # Get request body
        body = b""
        if hasattr(request, "body"):
            body = request.body() or b""

        # Get HTTP method and path
        method = "POST"
        path = "/"
        if hasattr(request, "method"):
            method = request.method
        if hasattr(request, "url"):
            path = str(request.url)

        # Create message to sign
        message = f"{method}\n{path}\n{timestamp}\n".encode() + body

        # Compute HMAC
        signature = hmac.new(
            self._secret_key.encode(),
            message,
            digestmod="sha256",
        ).hexdigest()

        return signature


class HMACValidator:
    """Validates HMAC signatures."""

    @staticmethod
    def generate_signature(
        method: str,
        path: str,
        timestamp: str,
        body: bytes,
        secret: str,
    ) -> str:
        """Generate HMAC signature."""
        message = f"{method}\n{path}\n{timestamp}\n".encode() + body
        return hmac.new(
            secret.encode(),
            message,
            digestmod="sha256",
        ).hexdigest()
