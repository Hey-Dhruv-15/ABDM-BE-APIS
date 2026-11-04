"""NABIDH connector adapter."""
from __future__ import annotations

import httpx
from fastapi import HTTPException, status

from app.connectors.base import BaseHealthConnector, ConnectorResult, ConnectorRuntimeContext, PatientSearchInput
from app.interoperability.canonical_response import canonicalize_nabidh_patient
from app.nabidh.auth import NabidhAuthError
from app.nabidh.client import NabidhClient
from app.settings import settings


class NabidhConnector(BaseHealthConnector):
    """Adapter for NABIDH FHIR APIs."""

    def __init__(self, client: NabidhClient) -> None:
        self._client = client

    async def patient_search(
        self,
        request_data: PatientSearchInput,
        runtime: ConnectorRuntimeContext,
    ) -> ConnectorResult:
        if not request_data.patient_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="patient_id is required for NABIDH")

        path = f"{settings.NABIDH_FHIR_BASE_PATH.rstrip('/')}/Patient/{request_data.patient_id}"
        try:
            upstream = await self._client.get(path)
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
        except (NabidhAuthError, httpx.HTTPError) as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

        resource = upstream if isinstance(upstream, dict) else {}
        return ConnectorResult(
            status="success",
            data={"patient": canonicalize_nabidh_patient(resource)},
            upstream=resource,
        )

