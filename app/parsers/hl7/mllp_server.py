"""
MLLP (Minimal Lower Layer Protocol) Server.
TCP server that listens for HL7 v2 messages wrapped in MLLP framing.
"""
import asyncio
import logging
import uuid
import traceback

from app.core.engine.context import RequestContext
# Note: Ideally the dependency injection resolves this, but since MLLP is standalone
# TCP (not FastAPI), we directly instansiate or use a global engine reference.
from app.core.engine.pipeline import PipelineEngine

logger = logging.getLogger(__name__)

# MLLP Framing characters
MLLP_START_BLOCK = b'\x0b'
MLLP_END_BLOCK = b'\x1c'
MLLP_CARRIAGE_RETURN = b'\x0d'

class MLLPServer:
    """Async TCP Server handling MLLP framed messages."""

    def __init__(self, host: str = "0.0.0.0", port: int = 2575, pipeline_engine: PipelineEngine = None):
        self.host = host
        self.port = port
        self.pipeline_engine = pipeline_engine or PipelineEngine()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Processes an incoming MLLP TCP connection."""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else "unknown"
        logger.info(f"Accepted MLLP connection from {client_addr}")

        try:
            # Read until the MLLP End Block + Carriage Return limit
            data = await reader.readuntil(MLLP_END_BLOCK + MLLP_CARRIAGE_RETURN)
            
            # Trim MLLP framing
            if data.startswith(MLLP_START_BLOCK):
                hl7_payload = data[1:-2] # Strip \x0b from start, \x1c\x0d from end
                
                # Setup context. In MLLP, the integration ID might be derived from 
                # a dedicated port mapping, or from the MSH segment.
                # Assuming port maps to integration "hl7_default" for this example.
                context = RequestContext(
                    correlation_id=str(uuid.uuid4()),
                    integration_id="hl7_default",
                    client_ip=client_ip
                )
                
                # Send to processing pipeline
                # In actual implementation we load the config properly for the context
                try:
                    await self.pipeline_engine.process(context, hl7_payload)
                    
                    # Generate simple success ACK
                    ack_msg = b"MSH|^~\\&|GATEWAY|RECEIVER|SENDER|SYSTEM|||ACK|1234|P|2.4\rMSA|AA|1234\r"
                    mllp_ack = MLLP_START_BLOCK + ack_msg + MLLP_END_BLOCK + MLLP_CARRIAGE_RETURN
                    
                    writer.write(mllp_ack)
                    await writer.drain()
                    
                except Exception as e:
                    logger.error(f"Pipeline error processing MLLP message: {e}")
                    # Generate Negative ACK (NACK)
                    nack_msg = b"MSH|^~\\&|GATEWAY|RECEIVER|SENDER|SYSTEM|||ACK|1234|P|2.4\rMSA|AE|1234|Internal Error\r"
                    mllp_nack = MLLP_START_BLOCK + nack_msg + MLLP_END_BLOCK + MLLP_CARRIAGE_RETURN
                    writer.write(mllp_nack)
                    await writer.drain()
            else:
                logger.warning("Received TCP data without valid MLLP Start Block")
                
        except asyncio.exceptions.IncompleteReadError:
            logger.warning("Connection closed before MLLP frame completed.")
        except Exception as e:
            logger.error(f"Error handling MLLP client: {e}\n{traceback.format_exc()}")
        finally:
            logger.info("Closing MLLP connection")
            writer.close()
            await writer.wait_closed()

    async def start(self):
        """Starts the MLLP TCP server listener."""
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        addr = server.sockets[0].getsockname()
        logger.info(f"Serving MLLP on {addr}")
        
        async with server:
            await server.serve_forever()

# Standalone start helper for tests or external runners
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mllp_server = MLLPServer()
    asyncio.run(mllp_server.start())
