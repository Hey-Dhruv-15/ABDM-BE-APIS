"""
HL7v2 Parser implementation.
"""
from typing import Any, Dict, Union

from app.parsers.base import BaseParser
from app.core.canonical.models import CanonicalMessage, ModelMetadata, Identifier, CanonicalDemographics
from app.core.exceptions import ParsingError
from app.parsers.hl7.validator import HL7Validator

class HL7Parser(BaseParser):
    """Parses and normalizes HL7v2 pipe-delimited messages."""

    async def parse(self, raw_payload: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
        """Convert raw pipe-delimited text into a nested dictionary structure."""
        if isinstance(raw_payload, dict):
            return raw_payload # already parsed somehow
            
        try:
            content = raw_payload.decode('utf-8') if isinstance(raw_payload, bytes) else raw_payload
            
            # Simple minimal segment parser. 
            # In production, use hl7 module (python-hl7)
            segments = content.strip().split('\r')
            if len(segments) == 1 and '\n' in content: 
                segments = content.strip().split('\n')
                
            parsed_data = {}
            for index, segment in enumerate(segments):
                fields = segment.split('|')
                segment_name = fields[0]
                # Store multiple instances of the same segment in a list
                if segment_name not in parsed_data:
                    parsed_data[segment_name] = []
                parsed_data[segment_name].append(fields)
                
            HL7Validator.validate(parsed_data)
            return parsed_data
            
        except Exception as e:
            if isinstance(e, ParsingError):
                raise
            raise ParsingError(f"Failed to parse HL7v2 payload: {str(e)}")

    def to_canonical(self, parsed_data: Dict[str, Any]) -> CanonicalMessage:
        """Map HL7 segments to the Canonical model."""
        
        msh = parsed_data.get("MSH", [[]])[0]
        pid = parsed_data.get("PID", [[]])[0] if "PID" in parsed_data else []
        
        source_system = msh[3] if len(msh) > 3 else "unknown"
        message_type = msh[9] if len(msh) > 9 else "unknown"
        
        identifiers = []
        demographics = None
        
        if pid:
            # PID.3 is Patient Identifier List
            if len(pid) > 3:
                patient_ids = pid[3].split('~')
                for pid_comp in patient_ids:
                    parts = pid_comp.split('^')
                    val = parts[0] if parts else None
                    if val:
                        identifiers.append(Identifier(
                            system="hl7_pid_3",
                            value=val,
                            type="mrn"
                        ))
            
            # PID.5 is Patient Name
            if len(pid) > 5:
                name_parts = pid[5].split('^')
                last_name = name_parts[0] if len(name_parts) > 0 else None
                first_name = name_parts[1] if len(name_parts) > 1 else None
                
                demographics = CanonicalDemographics(
                    first_name=first_name,
                    last_name=last_name,
                    dob=pid[7] if len(pid) > 7 else None,
                    gender=pid[8] if len(pid) > 8 else None
                )

        metadata = ModelMetadata(
            source_system=source_system,
            original_format="hl7v2",
            message_type=message_type
        )

        return CanonicalMessage(
            metadata=metadata,
            identifiers=identifiers,
            demographics=demographics,
            payload={"raw_segments": parsed_data} # Storing the parsed representation
        )
