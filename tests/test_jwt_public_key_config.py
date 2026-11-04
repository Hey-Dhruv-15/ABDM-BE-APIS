import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.security.oauth2 import JWTValidator


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_rs256_validation_accepts_escaped_newlines_in_public_key_pem():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    escaped_pem = public_key_pem.replace("\n", "\\n")

    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "gateway-user", "exp": 4102444800}
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    encoded_signature = _b64url(signature)
    token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    decoded_payload = JWTValidator.decode(
        token=token,
        secret="",
        algorithm="RS256",
        public_key_pem=escaped_pem,
    )

    assert decoded_payload["sub"] == "gateway-user"
