"""
Watcher for hot-reloading gateway configurations.
"""
import asyncio
from pathlib import Path
from typing import Callable, Any
from watchfiles import awatch
from app.logging.logger import get_logger

logger = get_logger(__name__)

class ConfigWatcher:
    """
    Watches configuration files for changes and executes a callback for hot reload.
    """

    def __init__(self, config_directory: str, on_change_callback: Callable[[], Any]):
        self.config_dir = Path(config_directory)
        self.on_change_callback = on_change_callback
        self._running = False
        self._task = None

    async def start(self) -> None:
        """Start watching for config file changes asynchronously."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info(f"Configuration watcher started on {self.config_dir}")

    async def stop(self) -> None:
        """Stop config file watcher."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Configuration watcher stopped")

    async def _watch_loop(self) -> None:
        """Process detected change events from the filesystem."""
        try:
            async for changes in awatch(str(self.config_dir)):
                if not self._running:
                    break
                
                # Check for yaml/yml changes
                yaml_changes = [c for c in changes if any(c[1].endswith(ext) for ext in (".yaml", ".yml"))]
                if yaml_changes:
                    logger.warning("Config changes detected: updating integrations")
                    # Trigger the reload callback
                    try:
                        # In real case, callback might be sync or async
                        if asyncio.iscoroutinefunction(self.on_change_callback):
                            await self.on_change_callback()
                        else:
                            self.on_change_callback()
                    except Exception as e:
                        logger.error(f"Error during hot reload: {e}")
        except Exception as e:
            logger.error(f"Config watcher error: {e}")
            self._running = False
