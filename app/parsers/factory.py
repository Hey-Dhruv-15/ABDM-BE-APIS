"""
Parser Factory.
Dynamically resolves and instantiates the appropriate parser based on configuration.
"""
from app.core.exceptions import ConfigurationError
from app.core.constants import FORMAT_FHIR, FORMAT_HL7V2
from app.parsers.base import BaseParser
from app.parsers.fhir.parser import FHIRParser
from app.parsers.hl7.parser import HL7Parser


class ParserFactory:
    """Factory to instantiate parsers based on format identifiers."""
    
    _registry = {
        FORMAT_FHIR: FHIRParser,
        FORMAT_HL7V2: HL7Parser,
    }

    @classmethod
    def get(cls, format_name: str) -> BaseParser:
        """
        Returns an instance of the requested parser.
        """
        parser_class = cls._registry.get(format_name.lower())
        
        if not parser_class:
            raise ConfigurationError(f"Unsupported parser format requested: '{format_name}'")
            
        return parser_class()
