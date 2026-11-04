"""My Health Record connector scaffold."""
from app.connectors.scaffolded import ScaffoldedNetworkConnector


class MyHealthRecordConnector(ScaffoldedNetworkConnector):
    """Placeholder adapter for Australia My Health Record."""

    def __init__(self) -> None:
        super().__init__("MY_HEALTH_RECORD")

