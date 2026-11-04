"""eHealth Exchange connector scaffold."""
from app.connectors.scaffolded import ScaffoldedNetworkConnector


class EHealthExchangeConnector(ScaffoldedNetworkConnector):
    """Placeholder adapter for USA eHealth Exchange."""

    def __init__(self) -> None:
        super().__init__("EHEALTH_EXCHANGE")

