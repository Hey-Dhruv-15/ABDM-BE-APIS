"""NEHR connector scaffold."""
from app.connectors.scaffolded import ScaffoldedNetworkConnector


class NEHRConnector(ScaffoldedNetworkConnector):
    """Placeholder adapter for Singapore NEHR."""

    def __init__(self) -> None:
        super().__init__("NEHR")

