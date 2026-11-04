"""
Configuration loader for gateway integrations.
"""
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import ValidationError
from app.config.schema import IntegrationConfig
from app.core.exceptions import ConfigurationError
from app.logging.logger import get_logger

logger = get_logger(__name__)

class ConfigLoader:
    """
    Loads and validates integration configurations from YAML.
    """

    def __init__(self, config_directory: str):
        self.config_dir = Path(config_directory)
        self.integrations: Dict[str, IntegrationConfig] = {}

    def load_all(self) -> Dict[str, IntegrationConfig]:
        """
        Scan and load all .yaml/.yml files in the config directory.
        """
        if not self.config_dir.is_dir():
            logger.error(f"Config directory {self.config_dir} does not exist")
            return {}

        new_integrations = {}
        for config_file in self.config_dir.glob("*.yaml"):
            try:
                configs = self._load_file(config_file)
                for config in configs:
                    new_integrations[config.name] = config
                logger.info(f"Loaded {len(configs)} configs from {config_file.name}")
            except Exception as e:
                logger.error(f"Error loading {config_file.name}: {str(e)}")
                # Depending on requirement, we could either fail all or just skip.
                # Let's fail for absolute consistency.
                raise ConfigurationError(f"Configuration error in {config_file.name}: {e}")

        self.integrations = new_integrations
        return self.integrations

    def _load_file(self, file_path: Path) -> List[IntegrationConfig]:
        """Load single YAML file and validate contents."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Allow single object or list of objects
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            raise ConfigurationError(f"YAML in {file_path.name} must be a dictionary or list")

        configs = []
        for item in data:
            try:
                config = IntegrationConfig(**item)
                configs.append(config)
            except ValidationError as e:
                raise ConfigurationError(f"Validation failed for {item.get('name', 'unknown')} in {file_path.name}: {e}")

        return configs

    def get_integration(self, name: str) -> Optional[IntegrationConfig]:
        """Retrieve a specific integration configuration by name."""
        return self.integrations.get(name)
