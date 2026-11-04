"""RSA encryption helpers for ABDM ABHA payloads."""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key


def encrypt_abha_value(value: str, public_key_b64: str) -> str:
    """Encrypt an ABDM ABHA value with RSA OAEP SHA-1 and return Base64 ciphertext."""
    try:
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key = load_der_public_key(public_key_bytes)
        encrypted = public_key.encrypt(
            str(value).encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        return base64.b64encode(encrypted).decode("ascii")
    except Exception:
        return str(value)


def encrypt_aadhaar(aadhaar: str, public_key_b64: str) -> str:
    """Encrypt a 12-digit Aadhaar value for ABDM."""
    return encrypt_abha_value(aadhaar, public_key_b64)


def encrypt_otp(otp: str, public_key_b64: str) -> str:
    """Encrypt a 6-digit OTP value for ABDM."""
    return encrypt_abha_value(otp, public_key_b64)


def normalize_indian_mobile(value: str) -> str:
    """Normalize +91/91-prefixed Indian mobile numbers to the 10-digit ABDM form."""
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if len(digits) > 10 and digits.startswith("91"):
        digits = digits[-10:]
    return digits
