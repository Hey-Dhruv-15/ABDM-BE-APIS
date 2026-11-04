"""
Core application exceptions.
Defines base and specific exception classes used across the system for predictable error handling.
"""

class GatewayException(Exception):
    """Base exception for all interoperability gateway errors."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class ConfigurationError(GatewayException):
    """Raised when integration configuration is invalid or missing."""
    def __init__(self, message: str):
        super().__init__(message, code="CONFIG_ERROR", status_code=500)


class ParsingError(GatewayException):
    """Raised when an incoming message cannot be parsed."""
    def __init__(self, message: str):
        super().__init__(message, code="PARSE_ERROR", status_code=400)


class ValidationError(GatewayException):
    """Raised when a message fails validation against schema or rules."""
    def __init__(self, message: str):
        super().__init__(message, code="VALIDATION_ERROR", status_code=422)


class TransformationError(GatewayException):
    """Raised when canonical model cannot be transformed to target format."""
    def __init__(self, message: str):
        super().__init__(message, code="TRANSFORM_ERROR", status_code=500)


class ProducerError(GatewayException):
    """Raised when sending a message to a downstream system fails."""
    def __init__(self, message: str):
        super().__init__(message, code="PRODUCER_ERROR", status_code=502)

# Security related exceptions
class SecurityError(GatewayException):
    """Raised when security validation (e.g., config error) fails."""
    def __init__(self, message: str):
        super().__init__(message, code="SECURITY_ERROR", status_code=500)

class AuthenticationError(GatewayException):
    """Raised when authentication fails."""
    def __init__(self, message: str):
        super().__init__(message, code="AUTH_ERROR", status_code=401)

class AuthorizationError(GatewayException):
    """Raised when authorization fails."""
    def __init__(self, message: str):
        super().__init__(message, code="FORBIDDEN", status_code=403)
