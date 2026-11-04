"""
Integration Router.
Responsible for resolving the correct integration configuration based on the RequestContext.
"""
import logging
from app.core.engine.context import RequestContext
from app.core.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

class IntegrationRouter:
    """
    Resolves and loads configurations for a specific integration.
    """
    def __init__(self, config_store=None):
        # config_store represents wherever configurations are kept in memory
        self.config_store = config_store or {}
        
    def resolve_context(self, context: RequestContext) -> RequestContext:
        """
        Populate the context with its corresponding integration configuration.
        """
        logger.debug(f"Routing integration: {context.integration_id}")
        
        # Mock Config lookup for now.
        # In a real setup, this would look into app.state.config or a loaded registry.
        mock_config = {
            "parser": "fhir",
            "transformer": "hl7v2",
            "producer": "http",
            "auth": "oauth2"
        }
        
        # In actual implementation:
        # config = self.config_store.get(context.integration_id)
        # if not config: raise ConfigurationError(...)
        
        context.integration_config = mock_config
        
        return context
