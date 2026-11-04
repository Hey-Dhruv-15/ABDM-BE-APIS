"""Fallback connector for networks without implemented adapters."""
from __future__ import annotations

from fastapi import HTTPException, status

from app.connectors.base import BaseHealthConnector, ConnectorResult, ConnectorRuntimeContext, PatientSearchInput


class UnsupportedConnector(BaseHealthConnector):
    """Raises explicit not-implemented error for unsupported networks."""

    def __init__(self, network: str) -> None:
        self._network = network

    async def patient_search(
        self,
        request_data: PatientSearchInput,
        runtime: ConnectorRuntimeContext,
    ) -> ConnectorResult:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Connector adapter for network '{self._network}' is not implemented yet",
        )

