"""ABHA connector adapter."""
from __future__ import annotations

from typing import Any, Dict

import httpx
from fastapi import HTTPException, status

from app.abdm.auth import ABDMAuthError
from app.abdm.client import ABDMGatewayClient
from app.connectors.base import BaseHealthConnector, ConnectorResult, ConnectorRuntimeContext, PatientSearchInput
from app.settings import settings
from app.utils.abha_validation import (
    build_validated_date_range,
    validate_consent_id,
    validate_data_push_url,
)


class AbhaConnector(BaseHealthConnector):
    """Adapter for ABDM/ABHA health information APIs."""

    def __init__(self, client: ABDMGatewayClient) -> None:
        self._client = client

    async def patient_search(
        self,
        request_data: PatientSearchInput,
        runtime: ConnectorRuntimeContext,
    ) -> ConnectorResult:
        consent_id = validate_consent_id(request_data.consent_id)
        data_push_url = validate_data_push_url(request_data.data_push_url or settings.GATEWAY_DEFAULT_DATA_PUSH_URL)
        if not data_push_url:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="GATEWAY_DEFAULT_DATA_PUSH_URL must be configured as an absolute https URL",
            )

        payload: Dict[str, Any] = {
            "request": {
                "consent": {"id": consent_id},
                "dateRange": build_validated_date_range(request_data.date_from, request_data.date_to),
                "dataPushUrl": data_push_url,
            }
        }

        try:
            upstream = await self._client.post(
                settings.ABDM_M2_HEALTH_INFO_REQUEST_PATH,
                payload,
                participant_id=settings.ABDM_HIU_ID or settings.ABDM_PARTICIPANT_ID,
                participant_type="HIU",
            )
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
        except (ABDMAuthError, httpx.HTTPError) as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

        return ConnectorResult(
            status="accepted",
            data={
                "mode": "async",
                "message": "Health information request submitted to ABHA gateway",
                "consent_id": consent_id,
            },
            upstream=upstream if isinstance(upstream, dict) else {"raw": upstream},
        )
