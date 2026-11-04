"""Kanta connector scaffold."""
from app.connectors.scaffolded import ScaffoldedNetworkConnector


class KantaConnector(ScaffoldedNetworkConnector):
    """Placeholder adapter for Finland Kanta."""

    def __init__(self) -> None:
        super().__init__("KANTA")

