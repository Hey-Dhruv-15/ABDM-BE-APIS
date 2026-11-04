"""OAuth2 authentication handler with JWT validation support."""
import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from app.core.exceptions import AuthenticationError
from app.logging.logger import get_logger

logger = get_logger(__name__)


class OAuth2Auth:
    """OAuth2 authentication handler."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._jwt_secret = self._config.get("jwt_secret")
        self._algorithm = self._config.get("algorithm", "HS256")
        self._token_endpoint = self._config.get("token_endpoint")
        self._client_id = self._config.get("client_id")

    async def authenticate(self, request: Any) -> bool:
        """
        Authenticate a request using OAuth2/JWT.

        Args:
            request: The incoming request.

        Returns:
            True if authentication succeeds.

        Raises:
            AuthenticationError: If authentication fails.
        """
        token = self._extract_token(request)

        if not token:
            logger.warning("OAuth2 token missing")
            raise AuthenticationError("OAuth2 token is required")

        try:
            JWTValidator.decode(
                token=token,
                secret=self._jwt_secret or "",
                algorithm=self._algorithm,
                issuer=self._config.get("issuer"),
                audience=self._config.get("audience"),
                public_key_pem=self._config.get("public_key_pem"),
            )
            return True
        except Exception as e:
            logger.warning(f"OAuth2 authentication failed: {e}")
            raise AuthenticationError(f"Invalid OAuth2 token: {e}")

    def _extract_token(self, request: Any) -> str | None:
        """Extract OAuth2 token from request."""
        auth_header = None
        if hasattr(request, "headers"):
            auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None


class JWTValidator:
    """Validates JWT tokens."""

    @staticmethod
    def decode(
        token: str,
        secret: str,
        algorithm: str = "HS256",
        issuer: str = "",
        audience: str = "",
        public_key_pem: str = "",
    ) -> dict[str, Any]:
        """Decode and validate a JWT token (HS256/RS256)."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        header = json.loads(JWTValidator._b64url_decode(parts[0]))
        payload = json.loads(JWTValidator._b64url_decode(parts[1]))
        signature = JWTValidator._b64url_decode(parts[2])
        signing_input = f"{parts[0]}.{parts[1]}".encode()

        alg = header.get("alg") or algorithm
        if alg == "HS256":
            if not secret:
                raise ValueError("Missing JWT secret for HS256 validation")
            expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError("JWT signature verification failed")
        elif alg == "RS256":
            if not public_key_pem:
                raise ValueError("Missing JWT public key for RS256 validation")
            normalized_public_key_pem = JWTValidator._normalize_public_key_pem(public_key_pem)
            public_key = serialization.load_pem_public_key(normalized_public_key_pem.encode())
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ValueError(f"Unsupported JWT algorithm: {alg}")

        now = int(datetime.now(timezone.utc).timestamp())
        exp = payload.get("exp")
        if exp is not None and now >= int(exp):
            raise ValueError("JWT token has expired")

        nbf = payload.get("nbf")
        if nbf is not None and now < int(nbf):
            raise ValueError("JWT token not yet valid")

        if issuer and payload.get("iss") != issuer:
            raise ValueError("JWT issuer mismatch")

        if audience:
            aud_claim = payload.get("aud")
            if isinstance(aud_claim, list):
                if audience not in aud_claim:
                    raise ValueError("JWT audience mismatch")
            elif aud_claim != audience:
                raise ValueError("JWT audience mismatch")

        return payload

    @staticmethod
    def _normalize_public_key_pem(public_key_pem: str) -> str:
        """Normalize PEM content supplied via environment variables or config."""
        if not public_key_pem:
            return ""
        normalized = str(public_key_pem).strip()
        normalized = normalized.replace("\\r\\n", "\n").replace("\\n", "\n")
        normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
        if normalized.startswith('"') and normalized.endswith('"') and len(normalized) >= 2:
            normalized = normalized[1:-1]
        return normalized.strip()

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        padding_len = (4 - len(data) % 4) % 4
        data += "=" * padding_len
        return base64.urlsafe_b64decode(data.encode())
