"""
Authentication factory for creating authentication handlers.

Factory pattern for creating authentication handlers based on configuration.
"""

from __future__ import annotations

from typing import Any

from app.core.constants import AuthType
from app.core.exceptions import SecurityError


class AuthFactory:
    """Factory for creating authentication handlers."""

    _handlers: dict[str, Any] = {}

    @classmethod
    def register(cls, auth_type: str, handler: Any) -> None:
        """Register an authentication handler."""
        cls._handlers[auth_type] = handler

    @classmethod
    def get_handler(cls, auth_type: str, config: dict[str, Any] | None = None) -> Any:
        """
        Get an authentication handler.

        Args:
            auth_type: The type of authentication.
            config: Configuration for the authentication handler.

        Returns:
            An authentication handler instance.

        Raises:
            SecurityError: If authentication type is not supported.
        """
        if auth_type == AuthType.NONE:
            return None

        if auth_type == AuthType.API_KEY:
            from app.security.api_key import APIKeyAuth
            return APIKeyAuth(config)
        if auth_type == AuthType.OAUTH2:
            from app.security.oauth2 import OAuth2Auth
            return OAuth2Auth(config)
        if auth_type == AuthType.MTLS:
            from app.security.mtls import mTLSAuth
            return mTLSAuth(config)
        if auth_type == AuthType.HMAC:
            from app.security.hmac import HMACAuth
            return HMACAuth(config)

        raise SecurityError(f"Unsupported authentication type: {auth_type}")
