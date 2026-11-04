"""
FHIR Parser implementation.
"""
import json
from typing import Any, Dict, Union

from app.parsers.base import BaseParser
from app.core.canonical.models import CanonicalMessage, ModelMetadata, Identifier, CanonicalDemographics
from app.core.exceptions import ParsingError
from app.parsers.fhir.validator import FHIRValidator


class FHIRParser(BaseParser):
    """Parses and normalizes FHIR JSON messages."""

    async def parse(self, raw_payload: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
        """Convert raw JSON into a Python dictionary."""
        if isinstance(raw_payload, dict):
            parsed = raw_payload
        else:
            try:
                # Handle bytes or string decoding
                content = raw_payload.decode('utf-8') if isinstance(raw_payload, bytes) else raw_payload
                parsed = json.loads(content)
            except json.JSONDecodeError as e:
                raise ParsingError(f"Invalid JSON payload: {str(e)}")
            except Exception as e:
                raise ParsingError(f"Failed to parse FHIR payload: {str(e)}")

        FHIRValidator.validate(parsed)
        return parsed

    def to_canonical(self, parsed_data: Dict[str, Any]) -> CanonicalMessage:
        """Map FHIR resources to the Canonical model."""
        
        # Determine the primary identifier
        identifiers = []
        for id_doc in parsed_data.get("identifier", []):
            if id_doc.get("value"):
                identifiers.append(Identifier(
                    system=id_doc.get("system", "unknown"),
                    value=id_doc.get("value"),
                    type="fhir_identifier"
                ))

        # Extract basic demographics if Patient
        demographics = None
        resource_type = parsed_data.get("resourceType", "Unknown")
        
        if resource_type == "Patient":
            names = parsed_data.get("name", [{}])
            primary_name = names[0] if names else {}
            
            demographics = CanonicalDemographics(
                first_name=primary_name.get("given", [""])[0] if primary_name.get("given") else None,
                last_name=primary_name.get("family"),
                dob=parsed_data.get("birthDate"),
                gender=parsed_data.get("gender")
            )

        metadata = ModelMetadata(
            source_system="fhir_endpoint",
            original_format="fhir",
            message_type=resource_type
        )

        return CanonicalMessage(
            metadata=metadata,
            identifiers=identifiers,
            demographics=demographics,
            payload=parsed_data
        )
