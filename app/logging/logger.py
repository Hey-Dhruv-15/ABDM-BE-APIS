"""
Structured JSON logging for the interoperability gateway.
Uses structlog for high-performance, context-aware logging.
"""
import logging
import sys
from typing import Any, Dict
import structlog
from app.logging.request_context import get_correlation_id

def configure_logging(log_level: str = "INFO"):
    """
    Initializes structlog with JSON rendering and standard processors.
    """
    # Define processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        # Inject correlation ID if available
        inject_correlation_id,
        structlog.processors.JSONRenderer()
    ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure standard logging to redirect to structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
    )

def inject_correlation_id(_, __, event_dict):
    """Processor to add correlation_id from contextvars to log entries."""
    correlation_id = get_correlation_id()
    if correlation_id:
        event_dict["correlation_id"] = correlation_id
    return event_dict

def get_logger(name: str):
    """Retrieve a named structlog logger."""
    return structlog.get_logger(name)
