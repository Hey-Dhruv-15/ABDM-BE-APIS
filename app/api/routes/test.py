from fastapi import APIRouter, Request, status
from app.logging.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

@router.post("/receiver")
async def test_receiver(request: Request):
    payload = await request.json()
    logger.info("Test receiver received payload", payload=payload)
    return {"status": "received", "data": payload}
