"""
MLLP producer for sending HL7 messages over TCP.
"""
import asyncio
from typing import Any, Dict, Optional
from app.producers.base import BaseProducer
from app.logging.logger import get_logger

logger = get_logger(__name__)

# MLLP Enveloping
SB = b"\x0b" # Start Block
EB = b"\x1c" # End Block
CR = b"\x0d" # Carriage Return

class MLLPSender(BaseProducer):
    """
    Producer that sends HL7 data via MLLP over TCP.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.host = self.config.get("host")
        self.port = self.config.get("port")
        self.timeout = self.config.get("timeout", 10.0)

    async def send(self, data: Any, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send data via MLLP TCP.
        """
        if not self.host or not self.port:
            raise ValueError("MLLP host or port not configured")

        if isinstance(data, str):
            payload = data.encode("utf-8")
        else:
            payload = data

        # Wrap in MLLP envelope
        mllp_message = SB + payload + EB + CR

        logger.info("Connecting to MLLP destination", host=self.host, port=self.port)
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.timeout
        )

        try:
            writer.write(mllp_message)
            await writer.drain()
            
            # Wait for ACK
            response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            
            # Basic ACK validation
            if SB in response and EB in response:
                logger.info("Received ACK from MLLP destination")
                return {
                    "status": "success",
                    "ack_received": True,
                    "response": response.decode("utf-8", errors="ignore")
                }
            else:
                logger.warning("Received invalid response from MLLP destination")
                return {
                    "status": "partial",
                    "ack_received": False,
                    "response": response.decode("utf-8", errors="ignore")
                }
        finally:
            writer.close()
            await writer.wait_closed()

    async def ping(self) -> bool:
        """Check if the MLLP destination is reachable."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
