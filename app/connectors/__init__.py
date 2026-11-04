"""Health-network connector adapters."""

from app.connectors.abha import AbhaConnector
from app.connectors.canada_health_infoway import CanadaHealthInfowayConnector
from app.connectors.danish_nhdn import DanishNHDNConnector
from app.connectors.ehealth_exchange import EHealthExchangeConnector
from app.connectors.kanta import KantaConnector
from app.connectors.my_health_record import MyHealthRecordConnector
from app.connectors.nabidh import NabidhConnector
from app.connectors.nehr import NEHRConnector
from app.connectors.nhs_spine import NHSSpineConnector
from app.connectors.unsupported import UnsupportedConnector

__all__ = [
    "AbhaConnector",
    "NabidhConnector",
    "NHSSpineConnector",
    "MyHealthRecordConnector",
    "EHealthExchangeConnector",
    "CanadaHealthInfowayConnector",
    "NEHRConnector",
    "KantaConnector",
    "DanishNHDNConnector",
    "UnsupportedConnector",
]
