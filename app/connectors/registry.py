"""Connector registry for resolving network adapters."""
from __future__ import annotations

from fastapi import HTTPException, status

from app.abdm.client import ABDMGatewayClient
from app.connectors.abha import AbhaConnector
from app.connectors.base import BaseHealthConnector
from app.connectors.canada_health_infoway import CanadaHealthInfowayConnector
from app.connectors.danish_nhdn import DanishNHDNConnector
from app.connectors.ehealth_exchange import EHealthExchangeConnector
from app.connectors.kanta import KantaConnector
from app.connectors.my_health_record import MyHealthRecordConnector
from app.connectors.nabidh import NabidhConnector
from app.connectors.nehr import NEHRConnector
from app.connectors.nhs_spine import NHSSpineConnector
from app.connectors.unsupported import UnsupportedConnector
from app.nabidh.client import NabidhClient


def resolve_connector(
    network: str,
    *,
    abdm_client: ABDMGatewayClient | None,
    nabidh_client: NabidhClient | None,
) -> BaseHealthConnector:
    """Return a concrete connector adapter for the resolved network."""
    normalized = network.strip().upper()
    if normalized == "ABHA":
        if not abdm_client:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="ABHA client unavailable")
        return AbhaConnector(abdm_client)

    if normalized == "NABIDH":
        if not nabidh_client:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="NABIDH client unavailable")
        return NabidhConnector(nabidh_client)

    if normalized == "NHS_SPINE":
        return NHSSpineConnector()

    if normalized == "MY_HEALTH_RECORD":
        return MyHealthRecordConnector()

    if normalized == "EHEALTH_EXCHANGE":
        return EHealthExchangeConnector()

    if normalized == "CANADA_HEALTH_INFOWAY":
        return CanadaHealthInfowayConnector()

    if normalized == "NEHR":
        return NEHRConnector()

    if normalized == "KANTA":
        return KantaConnector()

    if normalized == "DANISH_NHDN":
        return DanishNHDNConnector()

    return UnsupportedConnector(normalized or "UNKNOWN")
