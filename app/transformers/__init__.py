"""
Transformation layer for the interoperability gateway.
"""
from app.transformers.base import BaseTransformer
from app.transformers.registry import TransformerRegistry
from app.transformers.mapping_engine import MappingEngine

# Import subclasses to trigger registration
import app.transformers.fhir.to_fhir
import app.transformers.hl7.to_hl7

__all__ = ["BaseTransformer", "TransformerRegistry", "MappingEngine"]
