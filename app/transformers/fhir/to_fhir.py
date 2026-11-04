"""
Transformer for converting CanonicalMessage to FHIR R4.
"""
from typing import Any, Dict, Optional
from app.transformers.base import BaseTransformer
from app.transformers.registry import TransformerRegistry
from app.transformers.mapping_engine import MappingEngine
from app.core.canonical.models import CanonicalMessage

@TransformerRegistry.register("fhir")
class FHIRTransformer(BaseTransformer):
    """
    Transforms canonical messages to FHIR resources (JSON).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # In a real scenario, this mapping might be loaded from a file or DB
        self.mapping = {
            "resourceType": "const:Patient",
            "id": "id",
            "name.0.given.0": "demographics.first_name",
            "name.0.family": "demographics.last_name",
            "birthDate": "demographics.dob",
            "gender": "demographics.gender",
            "identifier.0.system": "identifiers.0.system",
            "identifier.0.value": "identifiers.0.value"
        }
        # Note: MappingEngine above doesn't support "const:" prefix yet, 
        # but we could extend it. For now, let's keep it simple.

    async def transform(self, message: CanonicalMessage) -> Dict[str, Any]:
        """
        Convert canonical message to FHIR Patient resource.
        """
        engine = MappingEngine(self.mapping)
        fhir_dict = engine.transform(message)
        
        # Hardcode resource type for this example
        fhir_dict["resourceType"] = "Patient"
        
        return fhir_dict

    @property
    def target_format(self) -> str:
        return "fhir"
