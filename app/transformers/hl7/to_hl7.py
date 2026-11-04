"""
Transformer for converting CanonicalMessage to HL7 v2.x.
"""
from typing import Any, Dict, Optional
from app.transformers.base import BaseTransformer
from app.transformers.registry import TransformerRegistry
from app.core.canonical.models import CanonicalMessage

@TransformerRegistry.register("hl7")
class HL7Transformer(BaseTransformer):
    """
    Transforms canonical messages to HL7 v2 pipe-delimited format.
    """

    async def transform(self, message: CanonicalMessage) -> str:
        """
        Convert canonical message to HL7 ADT^A01 (Simulated).
        """
        # In a real implementation, we would use an HL7 library like `hl7` or `python-hl7`
        # and follow a mapping definition.
        
        first_name = message.demographics.first_name if message.demographics else ""
        last_name = message.demographics.last_name if message.demographics else ""
        dob = message.demographics.dob if message.demographics else ""
        gender = message.demographics.gender if message.demographics else ""
        
        # MSH Segment
        msh = f"MSH|^~\\&|GATEWAY|ORG|RECEIVER|ORG|{message.metadata.received_at.strftime('%Y%m%d%H%M%S')}||ADT^A01|{message.id}|P|2.5"
        
        # PID Segment
        pid = f"PID|1||{message.identifiers[0].value if message.identifiers else ''}^^^MR||{last_name}^{first_name}||{dob}|{gender}"
        
        return f"{msh}\r{pid}\r"

    @property
    def target_format(self) -> str:
        return "hl7"
