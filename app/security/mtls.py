"""
mTLS (mutual TLS) authentication handler.
"""

from typing import Any

from app.core.exceptions import AuthenticationError
from app.logging.logger import get_logger

logger = get_logger(__name__)


class mTLSAuth:
    """mTLS (mutual TLS) authentication handler."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._cert_path = self._config.get("cert_path")
        self._key_path = self._config.get("key_path")
        self._ca_path = self._config.get("ca_path")
        self._verify_client = self._config.get("verify_client", True)

    async def authenticate(self, request: Any) -> bool:
        """
        Authenticate a request using mTLS.

        Args:
            request: The incoming request.

        Returns:
            True if authentication succeeds.

        Raises:
            AuthenticationError: If authentication fails.
        """
        # In production, TLS is handled at the connection level
        # This method validates the client certificate if present

        # Check if TLS is established
        if not hasattr(request, "client_cert"):
            logger.warning("No client certificate provided")
            if self._verify_client:
                raise AuthenticationError("Client certificate required for mTLS")
            return True

        cert = request.client_cert
        if not cert:
            logger.warning("Empty client certificate")
            if self._verify_client:
                raise AuthenticationError("Valid client certificate required")
            return True

        # Validate certificate
        try:
            self._validate_certificate(cert)
            return True
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            raise AuthenticationError(f"Certificate validation failed: {e}")

    def _validate_certificate(self, cert: Any) -> None:
        """Validate the client certificate."""
        # In production, implement full certificate validation
        # - Check expiration
        # - Verify against CA
        # - Check subject/issuer
        pass


class TLSConfig:
    """TLS configuration for mTLS."""

    def __init__(
        self,
        cert_path: str | None = None,
        key_path: str | None = None,
        ca_path: str | None = None,
    ) -> None:
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path

    @property
    def is_configured(self) -> bool:
        """Check if TLS is properly configured."""
        return bool(self.cert_path and self.key_path)
