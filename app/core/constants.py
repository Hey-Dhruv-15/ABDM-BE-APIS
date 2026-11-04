"""
Application wide constants.
"""
from enum import Enum

# Message Formats
FORMAT_FHIR = "fhir"
FORMAT_HL7V2 = "hl7v2"
FORMAT_JSON = "json"

# Protocol Types
PROTOCOL_HTTP = "http"
PROTOCOL_MLLP = "mllp"

# Header Keys
HEADER_INTEGRATION_ID = "X-Integration"
HEADER_CORRELATION_ID = "X-Correlation-ID"
HEADER_API_KEY = "X-Gateway-API-Key"
HEADER_REGION = "X-Region"
HEADER_HMAC_SIGNATURE = "X-Signature"
HEADER_HMAC_TIMESTAMP = "X-Timestamp"

# Default Values
DEFAULT_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3

class AuthType(str, Enum):
    """Authentication types."""
    NONE = "none"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    HMAC = "hmac"
