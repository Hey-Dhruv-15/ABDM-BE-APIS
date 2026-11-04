"""
FHIR Validator.
Performs basic structural checks on parsed FHIR dictionaries.
"""
from typing import Dict, Any
from app.core.exceptions import ParsingError

class FHIRValidator:
    """Validates basic FHIR structure."""
    
    @staticmethod
    def validate(parsed_data: Dict[str, Any]) -> None:
        """Ensure minimum FHIR requirements, such as resourceType presence."""
        if not isinstance(parsed_data, dict):
            raise ParsingError("FHIR payload must be a JSON object")

        if "resourceType" not in parsed_data:
            raise ParsingError("Missing required FHIR field: 'resourceType'")
            
        # In a real deployment, this would utilize fhir.resources library
        # for strict JSON schema compliance.
