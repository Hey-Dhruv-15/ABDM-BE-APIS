"""
Inbound processing endpoints for the Gateway.
Handles incoming messages from external systems.
"""
import logging
from typing import Any, Dict, Union

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.core.engine.context import RequestContext
from app.core.exceptions import (
    GatewayException,
    ParsingError,
    ValidationError,
    TransformationError,
    ProducerError
)
from app.api.dependencies import (
    get_pipeline_engine,
    RequestContextDep
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Inbound"], prefix="/inbound")


class InboundMessageRequest(BaseModel):
    """Request model for inbound message processing."""
    payload: Union[str, dict] = Field(
        ...,
        description="The message payload to process (string or JSON object)"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata to attach to the message"
    )


class InboundMessageResponse(BaseModel):
    """Response model for inbound message processing."""
    correlation_id: str
    status: str
    message: str
    integration_id: str
    result: Dict[str, Any] = Field(default_factory=dict)


@router.post(
    "/process",
    summary="Process inbound message",
    status_code=status.HTTP_200_OK,
    response_model=InboundMessageResponse,
)
async def process_inbound_message(
    request: InboundMessageRequest,
    context: RequestContextDep,
) -> InboundMessageResponse:
    """
    Process an inbound message from an external system.
    
    The message goes through the pipeline:
    1. Parse the incoming payload
    2. Validate against schema
    3. Transform to canonical model
    4. Validate canonical model
    5. Transform to target format
    6. Produce to downstream system
    
    Requires X-Integration header to route to the correct integration config.
    """
    engine = get_pipeline_engine()
    
    try:
        logger.info(
            f"Processing inbound message for integration [{context.integration_id}]",
            extra={
                "correlation_id": context.correlation_id,
                "integration_id": context.integration_id,
                "client_ip": context.client_ip
            }
        )
        
        # Process through pipeline (business logic in engine, not here)
        result = await engine.process(context, request.payload)
        
        logger.info(
            f"Inbound message processed successfully",
            extra={"correlation_id": context.correlation_id}
        )
        
        return InboundMessageResponse(
            correlation_id=context.correlation_id,
            status="processed",
            message="Message successfully processed through pipeline",
            integration_id=context.integration_id,
            result=result
        )
        
    except ParsingError as e:
        logger.warning(
            f"Parsing error for inbound message: {e.message}",
            extra={"correlation_id": context.correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "PARSE_ERROR",
                "message": e.message,
                "correlation_id": context.correlation_id
            }
        )
        
    except ValidationError as e:
        logger.warning(
            f"Validation error for inbound message: {e.message}",
            extra={"correlation_id": context.correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "VALIDATION_ERROR",
                "message": e.message,
                "correlation_id": context.correlation_id
            }
        )
        
    except TransformationError as e:
        logger.error(
            f"Transformation error for inbound message: {e.message}",
            extra={"correlation_id": context.correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "TRANSFORM_ERROR",
                "message": e.message,
                "correlation_id": context.correlation_id
            }
        )
        
    except ProducerError as e:
        logger.error(
            f"Producer error for inbound message: {e.message}",
            extra={"correlation_id": context.correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "PRODUCER_ERROR",
                "message": e.message,
                "correlation_id": context.correlation_id
            }
        )
        
    except GatewayException as e:
        logger.error(
            f"Gateway error processing inbound message: {e.message}",
            extra={"correlation_id": context.correlation_id}
        )
        raise HTTPException(
            status_code=e.status_code,
            detail={
                "error": e.code,
                "message": e.message,
                "correlation_id": context.correlation_id
            }
        )
        
    except Exception as e:
        logger.exception(
            f"Unexpected error processing inbound message",
            extra={"correlation_id": context.correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "correlation_id": context.correlation_id
            }
        )


@router.post(
    "/validate",
    summary="Validate inbound message without processing",
    status_code=status.HTTP_200_OK,
)
async def validate_inbound_message(
    request: InboundMessageRequest,
    context: RequestContextDep,
) -> Dict[str, Any]:
    """
    Validate an inbound message without processing it through the full pipeline.
    
    Useful for testing and debugging message formats.
    """
    # This would call a lighter validation without full pipeline processing
    # For now, return a placeholder response
    return {
        "valid": True,
        "correlation_id": context.correlation_id,
        "integration_id": context.integration_id,
        "message": "Validation endpoint - implementation pending"
    }
