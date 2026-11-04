"""
Core processing pipeline.
Orchestrates the lifecycle of an interoperability message:
 parse -> validate -> normalize -> transform -> produce
"""
from typing import Any, Dict, Optional
from app.core.engine.context import RequestContext
from app.core.canonical.models import CanonicalMessage
from app.core.canonical.validators import CanonicalValidator
from app.core.exceptions import (
    GatewayException, 
    ParsingError, 
    TransformationError, 
    ProducerError,
    ConfigurationError
)
from app.parsers.factory import ParserFactory
from app.transformers.registry import TransformerRegistry
from app.producers.factory import ProducerFactory
from app.logging.logger import get_logger
from app.logging.audit import AuditLogger

logger = get_logger(__name__)

class PipelineEngine:
    """
    The orchestrator for the gateway processing pipeline.
    Utilizes factories to dynamically select components based on integration configuration.
    """
    
    def __init__(self):
        # Configuration-driven engine. Dependencies are resolved at runtime via factories.
        pass
        
    async def process(self, context: RequestContext, raw_payload: Any) -> Dict[str, Any]:
        """
        Main execution flow for processing a message through the gateway.
        """
        correlation_id = context.correlation_id
        integration_name = context.integration_id
        
        logger.info("Pipeline processing started", 
                    correlation_id=correlation_id, 
                    integration=integration_name)
        
        AuditLogger.log_message_lifecycle(
            message_id=correlation_id,
            stage="INGRESS",
            status="success",
            integration_name=integration_name
        )
        
        try:
            # 1. Resolve Integration Components
            parser_type = context.get_config_value("parser")
            transformer_type = context.get_config_value("transformer")
            producer_type = context.get_config_value("producer")
            
            # 2. Parse & Normalize to Canonical
            logger.debug("Executing parsing step", parser=parser_type)
            parser = ParserFactory.get(parser_type)
            parsed_data = await parser.parse(raw_payload)
            canonical_model = parser.to_canonical(parsed_data)
            
            logger.debug("Successfully normalized to canonical model")
            AuditLogger.log_message_lifecycle(correlation_id, "PARSING", "success", integration_name)

            # 3. Validate Canonical Model
            logger.debug("Executing canonical validation")
            CanonicalValidator.validate(canonical_model)
            AuditLogger.log_message_lifecycle(correlation_id, "VALIDATION", "success", integration_name)

            # 4. Transform to Target Format
            logger.debug("Executing transformation step", transformer=transformer_type)
            transformer_cls = TransformerRegistry.get_transformer_class(transformer_type)
            # Instantiate with optional config from the integration context
            transformer = transformer_cls(context.integration_config.get("transformer_config"))
            target_payload = await transformer.transform(canonical_model)
            
            AuditLogger.log_message_lifecycle(correlation_id, "TRANSFORMATION", "success", integration_name)

            # 5. Produce to Target System
            logger.debug("Executing production step", producer=producer_type)
            # Target config is specifically passed to the producer
            target_config = context.integration_config.get("target_config", {})
            producer = ProducerFactory.create(producer_type, target_config)
            
            response = await producer.send(
                target_payload, 
                metadata={"correlation_id": correlation_id}
            )
            
            logger.info("Pipeline processing completed successfully", 
                        correlation_id=correlation_id)
            
            AuditLogger.log_message_lifecycle(
                message_id=correlation_id,
                stage="EGRESS",
                status="success",
                integration_name=integration_name,
                producer_response=response
            )
            
            return response

        except (ParsingError, TransformationError, ProducerError, ConfigurationError) as e:
            logger.error("Known pipeline error", 
                         error_type=type(e).__name__, 
                         detail=str(e), 
                         correlation_id=correlation_id)
            AuditLogger.log_message_lifecycle(correlation_id, "FAILURE", "failure", integration_name, error=str(e))
            raise
        except Exception as e:
            logger.exception("Unexpected pipeline failure", correlation_id=correlation_id)
            AuditLogger.log_message_lifecycle(correlation_id, "CRITICAL_FAILURE", "failure", integration_name, error=str(e))
            raise GatewayException(f"Pipeline execution failed: {str(e)}", code="PIPELINE_ERROR")

