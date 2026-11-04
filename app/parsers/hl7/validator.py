"""
HL7v2 Validator.
"""
from typing import Dict, Any
from app.core.exceptions import ParsingError

class HL7Validator:
    """Validates basic HL7v2 structure."""
    
    @staticmethod
    def validate(parsed_data: Dict[str, Any]) -> None:
        """Ensure minimum HL7 requirements, such as MSH presence."""
        if "MSH" not in parsed_data or not parsed_data["MSH"]:
            raise ParsingError("Missing required HL7 segment: 'MSH'")
            
        msh_segment = parsed_data["MSH"][0]
        if not msh_segment[0] == "MSH":
            raise ParsingError("Message must begin with MSH segment")
