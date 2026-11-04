"""
HTTP producer for sending messages to RESTful endpoints.
"""
import httpx
from typing import Any, Dict, Optional
from app.producers.base import BaseProducer
from app.utils.retry import retry_with_backoff
from app.logging.logger import get_logger

logger = get_logger(__name__)

class HTTPSender(BaseProducer):
    """
    Producer that sends data via HTTP/S POST.
    Supports configurable timeouts and retries.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.endpoint = self.config.get("endpoint")
        self.timeout = self.config.get("timeout", 30.0)
        self.headers = self.config.get("headers", {})
        self.auth = self.config.get("auth")
        
        # Default retry settings if not provided
        self.max_retries = self.config.get("max_retries", 3)
        self.retry_backoff = self.config.get("retry_backoff", 2.0)

    @retry_with_backoff(max_retries=3, min_delay=2.0, exceptions=(httpx.RequestError, httpx.HTTPStatusError))
    async def send(self, data: Any, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send data via HTTP POST.
        """
        if not self.endpoint:
            raise ValueError("HTTP endpoint not configured")

        headers = self.headers.copy()
        if metadata:
            # Propagate correlation IDs or other context if available
            if "correlation_id" in metadata:
                headers["X-Correlation-ID"] = metadata["correlation_id"]

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            logger.info("Sending message to HTTP endpoint", endpoint=self.endpoint)
            
            response = await client.post(
                self.endpoint,
                json=data if isinstance(data, dict) else None,
                content=data if isinstance(data, (str, bytes)) else None,
                headers=headers,
                auth=self.auth
            )
            
            response.raise_for_status()
            
            logger.info("Message sent successfully", status_code=response.status_code)
            return {
                "status": "success",
                "status_code": response.status_code,
                "response_body": response.text
            }

    async def ping(self) -> bool:
        """Check if the HTTP endpoint is reachable."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.get(self.endpoint)
                return response.status_code < 500
        except Exception:
            return False
