"""
Cryptographic signature utilities.
"""
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from app.core.exceptions import SecurityError

class SignatureValidator:
    """
    Validates digital signatures (e.g., RSA-SHA256).
    """

    @staticmethod
    def verify_rsa_signature(data: bytes, signature_b64: str, public_key_pem: str) -> bool:
        """
        Verify an RSA digital signature.
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            signature = base64.b64decode(signature_b64)
            
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            raise SecurityError(f"Signature verification failed: {str(e)}")
