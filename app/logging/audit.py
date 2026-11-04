"""
Audit logging for tracking sensitive operations and message lifecycle.
"""
from typing import Any, Dict, Optional
from datetime import datetime
from app.logging.logger import get_logger

logger = get_logger("audit")

class AuditLogger:
    """
    Standardized audit logger for security, compliance and traceability.
    """

    @staticmethod
    def log_event(
        event_type: str, 
        status: str, 
        details: Dict[str, Any], 
        user: Optional[str] = None
    ) -> None:
        """
        Record a structured audit event.
        """
        audit_payload = {
            "event_type": event_type,
            "status": status,
            "user": user or "system",
            "timestamp": datetime.utcnow().isoformat(),
            **details
        }
        
        # High-severity logs if status is failure
        if status == "failure":
            logger.error("Audit Event", **audit_payload)
        else:
            logger.info("Audit Event", **audit_payload)

    @staticmethod
    def log_message_lifecycle(
        message_id: str,
        stage: str,
        status: str,
        integration_name: str,
        **extra: Any
    ) -> None:
        """
        Specialized audit log for tracking a message through the interoperability pipeline.
        """
        details = {
            "message_id": message_id,
            "stage": stage,
            "integration_name": integration_name,
            **extra
        }
        AuditLogger.log_event("message_lifecycle", status, details)
