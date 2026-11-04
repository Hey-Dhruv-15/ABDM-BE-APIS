"""Placeholder connector for networks wired but not yet integrated."""
from __future__ import annotations

from app.connectors.base import ConnectorResult, ConnectorRuntimeContext, PatientSearchInput
from app.connectors.unsupported import UnsupportedConnector


class ScaffoldedNetworkConnector(UnsupportedConnector):
    """Explicit scaffold connector used until a real adapter is implemented."""

    async def patient_search(
        self,
        request_data: PatientSearchInput,
        runtime: ConnectorRuntimeContext,
    ) -> ConnectorResult:
        return await super().patient_search(request_data=request_data, runtime=runtime)

