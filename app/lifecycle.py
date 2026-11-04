"""
Application lifecycle management for FastAPI.
Handles startup and shutdown events, including configuration loading and resource initialization.
"""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.settings import settings
from app.config.loader import ConfigLoader
from app.config.watcher import ConfigWatcher
from app.core.engine.pipeline import PipelineEngine
from app.abdm.auth import ABDMAuthService
from app.abdm.client import ABDMGatewayClient
from app.nabidh.auth import NabidhAuthService
from app.nabidh.client import NabidhClient
from app.api.dependencies import (
    set_config_loader,
    set_pipeline_engine,
    set_abdm_auth_service,
    set_abdm_gateway_client,
    set_nabidh_auth_service,
    set_nabidh_client,
)
from app.logging.logger import configure_logging, get_logger

logger = get_logger(__name__)

async def _sync_ngrok_bridge_url(client: ABDMGatewayClient):
    """Detect configured or active ngrok/domain bridge URL and auto-sync with ABDM Gateway."""
    try:
        import httpx
        from urllib.parse import urlparse
        from uuid import uuid4
        from datetime import datetime, timezone

        public_url = getattr(settings, "ABDM_BRIDGE_URL", None)

        # Fallback 1: Derive root host from GATEWAY_DEFAULT_DATA_PUSH_URL if configured with https
        if not public_url and getattr(settings, "GATEWAY_DEFAULT_DATA_PUSH_URL", None):
            push_url = settings.GATEWAY_DEFAULT_DATA_PUSH_URL.strip()
            if push_url.startswith("https://") and "yourserver.com" not in push_url:
                parsed = urlparse(push_url)
                public_url = f"{parsed.scheme}://{parsed.netloc}"

        # Fallback 2: Query local active ngrok agent (http://127.0.0.1:4040)
        if not public_url:
            try:
                async with httpx.AsyncClient() as http_client:
                    res = await http_client.get("http://127.0.0.1:4040/api/tunnels", timeout=1.0)
                    if res.status_code == 200:
                        tunnels = res.json().get("tunnels", [])
                        public_url = next((t.get("public_url") for t in tunnels if isinstance(t, dict) and t.get("public_url", "").startswith("https")), None)
            except Exception:
                pass

        if public_url:
            clean_url = public_url.rstrip("/")
            headers = {
                "REQUEST-ID": str(uuid4()),
                "TIMESTAMP": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "X-CM-ID": settings.ABDM_CM_ID or "sbx",
                "X-Region": settings.REGION or "india",
                "X-Integration": settings.ABDM_INTEGRATION_ID or "test-relay",
            }
            await client.patch(
                "/api/hiecm/gateway/v3/bridge/url",
                {"url": clean_url},
                extra_headers=headers
            )
            logger.info("Auto-registered Bridge URL with ABDM Gateway on startup", url=clean_url)
    except Exception as exc:
        logger.warning("Bridge URL auto-sync skipped", reason=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle.
    """
    # --- Startup phase ---
    # 1. Initialize Loggers
    configure_logging(log_level=settings.LOG_LEVEL)
    logger.info("Initializing application", project=settings.PROJECT_NAME, env=settings.ENVIRONMENT)
    
    # 2. Load Configurations
    loader = ConfigLoader(settings.CONFIG_PATH)
    loader.load_all()
    set_config_loader(loader)
    
    # 3. Initialize Engine
    engine = PipelineEngine()
    set_pipeline_engine(engine)

    # 4. Initialize ABDM services
    abdm_auth_service = ABDMAuthService()
    abdm_gateway_client = ABDMGatewayClient(abdm_auth_service)
    set_abdm_auth_service(abdm_auth_service)
    set_abdm_gateway_client(abdm_gateway_client)

    # 5. Start Config Watcher (Hot Reload)
    if settings.ENABLE_NABIDH:
        nabidh_auth_service = NabidhAuthService()
        nabidh_client = NabidhClient(nabidh_auth_service)
        set_nabidh_auth_service(nabidh_auth_service)
        set_nabidh_client(nabidh_client)

    # 5. Start Config Watcher (Hot Reload)
    watcher = None
    if getattr(settings, "CONFIG_WATCH_ENABLED", True):
        watcher = ConfigWatcher(settings.CONFIG_PATH, on_change_callback=loader.load_all)
        await watcher.start()
    
    # 6. Initialize local JSON stores and seed ABHA address linkages to workflow store
    try:
        from app.abdm.json_storage import init_storage, read_storage
        from app.orchestration.abha_state import abha_workflow_store
        init_storage()
        all_contexts = read_storage("care_contexts")
        seeded_count = 0
        for val in all_contexts.values():
            if isinstance(val, dict) and val.get("abhaAddress"):
                abha_workflow_store.seed_abha_address(val.get("abhaAddress"))
                seeded_count += 1
        logger.info("Successfully seeded workflow store patient linkages from care_contexts.json", count=seeded_count)
    except Exception as exc:
        logger.warning("Failed to seed workflow store patient linkages on startup", error=str(exc))

    # 7. Auto-detect and register active local Ngrok tunnel with ABDM Gateway
    if getattr(settings, "ABDM_BRIDGE_URL", None):
        asyncio.create_task(_sync_ngrok_bridge_url(abdm_gateway_client))

    # 8. Initialize & Seed MongoDB clinical & master data for ABDM data push
    try:
        from app.db.mongo_manager import MongoDBManager
        MongoDBManager.seed_initial_data()
    except Exception as exc:
        logger.debug("MongoDB auto-seed on startup skipped", reason=str(exc))

    logger.info("Application startup complete")
    
    # Yield control to the application
    yield
    
    # --- Shutdown phase ---
    logger.info("Shutting down application")
    if watcher:
        await watcher.stop()
