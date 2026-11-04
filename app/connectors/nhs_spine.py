"""NHS Spine connector scaffold."""
from app.connectors.scaffolded import ScaffoldedNetworkConnector


class NHSSpineConnector(ScaffoldedNetworkConnector):
    """Placeholder adapter for UK NHS Spine."""

    def __init__(self) -> None:
        super().__init__("NHS_SPINE")

