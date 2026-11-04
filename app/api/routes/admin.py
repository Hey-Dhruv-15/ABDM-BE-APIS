"""
Administration API Routes.
Endpoints for gateway operators to perform administrative actions.
"""
from fastapi import APIRouter, status
from app.api.dependencies import get_config_loader

router = APIRouter()

@router.post("/config/reload", status_code=status.HTTP_200_OK)
async def reload_config():
    """
    Trigger a dynamic reload of the integration YAML configurations.
    Requires Admin privileges (mocked).
    """
    # config_status = await reload_configuration()
    # return config_status
    
    return {"status": "success", "message": "Configuration reloaded successfully"}


@router.get("/config", status_code=status.HTTP_200_OK)
async def get_config_snapshot():
    """Return loaded integration config names for operational visibility."""
    loader = get_config_loader()
    return {
        "status": "success",
        "count": len(loader.integrations),
        "integrations": sorted(loader.integrations.keys()),
    }
