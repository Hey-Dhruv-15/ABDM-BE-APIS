"""
Canonical model validation rules.
Validates the internal canonical representation before it's passed down the pipeline.
"""
from app.core.canonical.models import CanonicalMessage
from app.core.exceptions import ValidationError

class CanonicalValidator:
    """Business logic validations on the canonical model."""
    
    @staticmethod
    def validate(message: CanonicalMessage) -> None:
        """
        Verify that canonical structure meets minimum business requirements.
        Raises ValidationError if checks fail.
        """
        if not message.metadata:
            raise ValidationError("Canonical message is missing metadata")
        
        if not message.metadata.source_system:
            raise ValidationError("Canonical message must have a source system")
            
        if not message.identifiers and not message.payload:
            raise ValidationError("Canonical message must contain at least one identifier or payload data")
            
        # Additional deep validations can be implemented here based on message_type
