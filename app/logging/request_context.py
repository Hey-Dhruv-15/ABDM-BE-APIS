"""
Request context management for tracking correlation IDs throughout the pipeline.
"""
import uuid
import contextvars
from typing import Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Context variables for tracking
correlation_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("correlation_id", default=None)

def set_correlation_id(correlation_id: str) -> None:
    correlation_id_ctx.set(correlation_id)

def get_correlation_id() -> Optional[str]:
    return correlation_id_ctx.get()

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts or generates a correlation ID for every request
    and propagates it to the logging context and response headers.
    """
    async def dispatch(self, request: Request, call_next):
        # 1. Get correlation ID from header or generate new one
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        
        # 2. Set in context for logging
        token = correlation_id_ctx.set(correlation_id)
        
        try:
            response: Response = await call_next(request)
            # 3. Add to response header
            response.headers["X-Correlation-ID"] = correlation_id
            return response
        finally:
            # 4. Clean up context
            correlation_id_ctx.reset(token)
