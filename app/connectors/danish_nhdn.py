"""Danish NHDN connector scaffold."""
from app.connectors.scaffolded import ScaffoldedNetworkConnector


class DanishNHDNConnector(ScaffoldedNetworkConnector):
    """Placeholder adapter for Denmark Danish NHDN."""

    def __init__(self) -> None:
        super().__init__("DANISH_NHDN")

