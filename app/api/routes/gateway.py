
"""Unified gateway orchestration routes."""
from typing import Any, Dict

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.abdm.auth import ABDMAuthError
from app.abdm.client import ABDMGatewayClient
from app.api.dependencies import RequestContextDep, get_abdm_gateway_client, get_nabidh_client_optional
from app.compliance.consent import PatientSearchPolicyInput, enforce_patient_search_consent
from app.connectors.base import ConnectorRuntimeContext, PatientSearchInput
from app.connectors.networks import ALL_KNOWN_NETWORKS, IMPLEMENTED_NETWORKS
from app.connectors.registry import resolve_connector
from app.interoperability.canonical_response import build_gateway_response
from app.nabidh.auth import NabidhAuthError
from app.nabidh.client import NabidhClient
from app.orchestration.abha_state import abha_workflow_store
from app.settings import settings
from app.utils.abha_validation import (
    build_validated_date_range,
    normalize_abha_number,
    validate_consent_id,
    validate_data_push_url,
)

router = APIRouter(prefix="/gateway", tags=["Gateway"])


class PatientSearchRequest(BaseModel):
    """Unified patient search request (ABHA-focused)."""

    patient_id: str | None = Field(default=None, examples=["abha-number-or-fhir-id"])
    consent_id: str | None = Field(default=None, examples=["consent-id"])
    purpose: str = Field(default="Treatment", examples=["Treatment"])
    date_from: str | None = Field(default=None, examples=["2024-01-01T00:00:00Z"])
    date_to: str | None = Field(default=None, examples=["2026-01-01T00:00:00Z"])
    data_push_url: str | None = Field(default=None, examples=["https://yourserver.com/health-data"])


class PatientDiscoverRequest(BaseModel):
    """Discovery request to locate patient records in a target network."""

    patient_id: str | None = Field(default=None, examples=["abha-number-or-local-id"])
    abha_number: str | None = Field(default=None, examples=["91XXXXXXXXXX"])
    identifier: str | None = Field(default=None, examples=["MRN12345"])


class HealthRecordsFetchRequest(BaseModel):
    """Fetch health records after patient discovery and consent."""

    patient_id: str | None = Field(default=None, examples=["abha-number-or-fhir-id"])
    consent_id: str | None = Field(default=None, examples=["consent-id"])
    purpose: str = Field(default="Treatment", examples=["Treatment"])
    date_from: str | None = Field(default=None, examples=["2024-01-01T00:00:00Z"])
    date_to: str | None = Field(default=None, examples=["2026-01-01T00:00:00Z"])
    data_push_url: str | None = Field(default=None, examples=["https://yourserver.com/health-data"])


class ConsentRequestBody(BaseModel):
    """Gateway-level consent request wrapper payload."""

    request: Dict[str, Any]
    model_config = ConfigDict(extra="allow")


@router.post("/patient/search", status_code=status.HTTP_200_OK)
async def patient_search(
    body: PatientSearchRequest,
    request: Request,
    context: RequestContextDep,
    abdm_client: ABDMGatewayClient = Depends(get_abdm_gateway_client),
    nabidh_client: NabidhClient | None = Depends(get_nabidh_client_optional),
) -> Dict[str, Any]:
    """Backward-compatible wrapper: discover (no consent) or fetch (with consent)."""
    if body.consent_id:
        return await _fetch_health_records_internal(
            body=HealthRecordsFetchRequest(**body.model_dump(exclude_none=True)),
            request=request,
            context=context,
            abdm_client=abdm_client,
            nabidh_client=nabidh_client,
        )

    return await _discover_patient_internal(
        body=PatientDiscoverRequest(**body.model_dump(exclude_none=True)),
        request=request,
        context=context,
        abdm_client=abdm_client,
        nabidh_client=nabidh_client,
    )


async def _discover_patient_internal(
    *,
    body: PatientDiscoverRequest,
    request: Request,
    context: RequestContextDep,
    abdm_client: ABDMGatewayClient,
    nabidh_client: NabidhClient | None,
) -> Dict[str, Any]:
    """Discover patient data location/identity in the resolved health network."""
    network = (getattr(request.state, "health_network", "") or "").upper()
    region = getattr(request.state, "region", None)
    if network == "ABHA":
        abha_number_raw = (body.abha_number or body.patient_id or "").strip()
        if not abha_number_raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="abha_number or patient_id is required for ABHA patient discovery",
            )
        abha_number = normalize_abha_number(abha_number_raw)
        if not settings.ABDM_M2_PATIENT_DISCOVER_PATH.strip():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ABDM_M2_PATIENT_DISCOVER_PATH is not configured",
            )
        payload = {"abhaNumber": abha_number}
        try:
            upstream = await abdm_client.post(
                settings.ABDM_M2_PATIENT_DISCOVER_PATH,
                payload,
                participant_id=settings.ABDM_HIU_ID or settings.ABDM_PARTICIPANT_ID,
                participant_type="HIU",
            )
        except httpx.HTTPStatusError as exc:
            _raise_upstream_http_error(exc)
        except (ABDMAuthError, httpx.HTTPError) as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

        upstream_payload = upstream if isinstance(upstream, dict) else {"raw": upstream}
        await abha_workflow_store.upsert_request(
            correlation_id=context.correlation_id,
            consent_id=_extract_consent_id(upstream_payload),
            transaction_id=_extract_transaction_id(upstream_payload),
            payload={
                "operation": "patient/discover",
                "request": payload,
            },
        )
        return build_gateway_response(
            correlation_id=context.correlation_id,
            region=region,
            network=network,
            status="accepted",
            data={"message": "Patient discovery request submitted"},
            upstream=upstream_payload,
        )

    if network == "NABIDH":
        if not nabidh_client:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="NABIDH client unavailable")
        identifier = (body.identifier or body.patient_id or "").strip()
        if not identifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="identifier or patient_id is required for NABIDH patient discovery",
            )
        path = f"{settings.NABIDH_FHIR_BASE_PATH.rstrip('/')}/Patient?identifier={identifier}"
        try:
            upstream = await nabidh_client.get(path)
        except httpx.HTTPStatusError as exc:
            _raise_upstream_http_error(exc)
        except (NabidhAuthError, httpx.HTTPError) as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

        upstream_payload = upstream if isinstance(upstream, dict) else {"raw": upstream}
        return build_gateway_response(
            correlation_id=context.correlation_id,
            region=region,
            network=network,
            status="success",
            data={"message": "Patient discovery completed"},
            upstream=upstream_payload,
        )

    connector = resolve_connector(network, abdm_client=abdm_client, nabidh_client=nabidh_client)
    await connector.patient_search(
        PatientSearchInput(
            patient_id=body.patient_id,
            consent_id=None,
            purpose="DISCOVER",
            date_from=None,
            date_to=None,
            data_push_url=None,
        ),
        ConnectorRuntimeContext(
            correlation_id=context.correlation_id,
            region=region,
            network=network,
        ),
    )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=f"Patient discovery flow is not implemented for network '{network}' yet",
    )


async def _fetch_health_records_internal(
    *,
    body: HealthRecordsFetchRequest,
    request: Request,
    context: RequestContextDep,
    abdm_client: ABDMGatewayClient,
    nabidh_client: NabidhClient | None,
) -> Dict[str, Any]:
    """Fetch health records in the resolved network."""
    network = (getattr(request.state, "health_network", "") or "").upper()
    region = getattr(request.state, "region", None)
    enforce_patient_search_consent(
        PatientSearchPolicyInput(
            network=network,
            consent_id=body.consent_id,
            purpose=body.purpose,
        )
    )

    if network == "ABHA":
        consent_id = validate_consent_id(body.consent_id)
        data_push_url = validate_data_push_url(body.data_push_url or settings.GATEWAY_DEFAULT_DATA_PUSH_URL)
        if not data_push_url:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="GATEWAY_DEFAULT_DATA_PUSH_URL must be configured as an absolute https URL",
            )
        payload = {
            "request": {
                "consent": {"id": consent_id},
                "dateRange": build_validated_date_range(body.date_from, body.date_to),
                "dataPushUrl": data_push_url,
            }
        }
        try:
            upstream = await abdm_client.post(
                settings.ABDM_M2_HEALTH_INFO_REQUEST_PATH,
                payload,
                participant_id=settings.ABDM_HIU_ID or settings.ABDM_PARTICIPANT_ID,
                participant_type="HIU",
            )
        except httpx.HTTPStatusError as exc:
            _raise_upstream_http_error(exc)
        except (ABDMAuthError, httpx.HTTPError) as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

        upstream_payload = upstream if isinstance(upstream, dict) else {"raw": upstream}
        await abha_workflow_store.upsert_request(
            correlation_id=context.correlation_id,
            consent_id=consent_id,
            transaction_id=_extract_transaction_id(upstream_payload),
            payload={
                "operation": "health-records/fetch",
                "request": payload,
            },
        )
        return build_gateway_response(
            correlation_id=context.correlation_id,
            region=region,
            network=network,
            status="accepted",
            data={
                "mode": "async",
                "message": "Health information request submitted to ABHA gateway",
                "consent_id": consent_id,
            },
            upstream=upstream_payload,
        )

    connector = resolve_connector(network, abdm_client=abdm_client, nabidh_client=nabidh_client)
    result = await connector.patient_search(
        PatientSearchInput(
            patient_id=body.patient_id,
            consent_id=body.consent_id,
            purpose=body.purpose,
            date_from=body.date_from,
            date_to=body.date_to,
            data_push_url=body.data_push_url,
        ),
        ConnectorRuntimeContext(
            correlation_id=context.correlation_id,
            region=region,
            network=network,
        ),
    )
    return build_gateway_response(
        correlation_id=context.correlation_id,
        region=region,
        network=network,
        status=result.status,
        data=result.data,
        upstream=result.upstream,
    )


@router.post("/patient/discover", status_code=status.HTTP_200_OK)
async def patient_discover(
    body: PatientDiscoverRequest,
    request: Request,
    context: RequestContextDep,
    abdm_client: ABDMGatewayClient = Depends(get_abdm_gateway_client),
    nabidh_client: NabidhClient | None = Depends(get_nabidh_client_optional),
) -> Dict[str, Any]:
    """Discover patient identifiers and data locations across networks."""
    return await _discover_patient_internal(
        body=body,
        request=request,
        context=context,
        abdm_client=abdm_client,
        nabidh_client=nabidh_client,
    )


@router.post("/health-records/fetch", status_code=status.HTTP_200_OK)
async def fetch_health_records(
    body: HealthRecordsFetchRequest,
    request: Request,
    context: RequestContextDep,
    abdm_client: ABDMGatewayClient = Depends(get_abdm_gateway_client),
    nabidh_client: NabidhClient | None = Depends(get_nabidh_client_optional),
) -> Dict[str, Any]:
    """Fetch records after discovery and consent checks."""
    return await _fetch_health_records_internal(
        body=body,
        request=request,
        context=context,
        abdm_client=abdm_client,
        nabidh_client=nabidh_client,
    )


@router.post("/consent/request", status_code=status.HTTP_200_OK)
async def consent_request(
    body: ConsentRequestBody,
    request: Request,
    context: RequestContextDep,
    abdm_client: ABDMGatewayClient = Depends(get_abdm_gateway_client),
) -> Dict[str, Any]:
    """Submit a consent request via ABDM for ABHA-based flows."""
    network = (getattr(request.state, "health_network", "") or "").upper()
    region = getattr(request.state, "region", None)
    if not network:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to resolve health network for this request",
        )

    if network != "ABHA" and network in ALL_KNOWN_NETWORKS:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Consent request flow is not implemented for network '{network}' yet",
        )

    if network != "ABHA" and network not in IMPLEMENTED_NETWORKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported network '{network}' for consent request",
        )

    payload = body.model_dump(by_alias=True, exclude_none=True)
    _apply_default_participants(payload)
    try:
        upstream = await abdm_client.post(
            settings.ABDM_M2_CONSENT_REQUEST_INIT_PATH,
            payload,
            participant_id=settings.ABDM_HIU_ID or settings.ABDM_PARTICIPANT_ID,
            participant_type="HIU",
        )
    except httpx.HTTPStatusError as exc:
        _raise_upstream_http_error(exc)
    except (ABDMAuthError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    upstream_payload = upstream if isinstance(upstream, dict) else {"raw": upstream}
    await abha_workflow_store.upsert_request(
        correlation_id=context.correlation_id,
        consent_request_id=_extract_consent_request_id(upstream_payload),
        consent_id=_extract_consent_id(upstream_payload),
        transaction_id=_extract_transaction_id(upstream_payload),
        payload={
            "operation": "consent/request",
            "request": payload,
        },
    )

    return build_gateway_response(
        correlation_id=context.correlation_id,
        region=region,
        network=network or "ABHA",
        status="accepted",
        data={"message": "Consent request submitted"},
        upstream=upstream_payload,
    )


@router.get("/consent/{consent_id}", status_code=status.HTTP_200_OK)
async def get_consent_status(
    consent_id: str,
    request: Request,
    context: RequestContextDep,
    abdm_client: ABDMGatewayClient = Depends(get_abdm_gateway_client),
) -> Dict[str, Any]:
    """Fetch consent status from the network."""
    consent_id = validate_consent_id(consent_id)
    network = (getattr(request.state, "health_network", "") or "").upper()
    region = getattr(request.state, "region", None)
    if network != "ABHA":
        if network in ALL_KNOWN_NETWORKS:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail=f"Consent status flow is not implemented for network '{network}' yet",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported network '{network}' for consent status",
        )

    if not settings.ABDM_M2_CONSENT_STATUS_PATH_TEMPLATE.strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ABDM_M2_CONSENT_STATUS_PATH_TEMPLATE is not configured",
        )

    consent_path = settings.ABDM_M2_CONSENT_STATUS_PATH_TEMPLATE.format(consent_id=consent_id)
    try:
        upstream = await abdm_client.get(
            consent_path,
            participant_id=settings.ABDM_HIU_ID or settings.ABDM_PARTICIPANT_ID,
            participant_type="HIU",
        )
    except httpx.HTTPStatusError as exc:
        _raise_upstream_http_error(exc)
    except (ABDMAuthError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    upstream_payload = upstream if isinstance(upstream, dict) else {"raw": upstream}
    await abha_workflow_store.upsert_request(
        correlation_id=context.correlation_id,
        consent_id=consent_id,
        payload={
            "operation": "consent/status",
            "request": {"consent_id": consent_id},
        },
    )
    return build_gateway_response(
        correlation_id=context.correlation_id,
        region=region,
        network=network,
        status="success",
        data={"message": "Consent status fetched"},
        upstream=upstream_payload,
    )


@router.get("/transactions/{correlation_id}", status_code=status.HTTP_200_OK)
async def get_transaction_status(correlation_id: str) -> Dict[str, Any]:
    """Fetch correlated async workflow state for a gateway request."""
    record = await abha_workflow_store.get(correlation_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No workflow state found for correlation_id '{correlation_id}'",
        )
    return record


def _apply_default_participants(payload: Dict[str, Any]) -> None:
    """Best-effort participant auto-fill for consent requests."""
    request = payload.setdefault("request", {})
    if not isinstance(request, dict):
        return
    consent = request.get("consent")
    if not isinstance(consent, dict):
        return

    if settings.ABDM_HIU_ID:
        hiu = consent.setdefault("hiu", {})
        if isinstance(hiu, dict) and not hiu.get("id"):
            hiu["id"] = settings.ABDM_HIU_ID

    if settings.ABDM_HIP_ID:
        hip = consent.setdefault("hip", {})
        if isinstance(hip, dict) and not hip.get("id"):
            hip["id"] = settings.ABDM_HIP_ID


def _raise_upstream_http_error(exc: httpx.HTTPStatusError) -> None:
    """Convert upstream HTTP error to a debuggable API error payload."""
    response = exc.response
    raise HTTPException(
        status_code=response.status_code,
        detail={
            "message": response.text,
            "upstreamStatus": response.status_code,
            "upstreamUrl": str(response.request.url),
            "upstreamRequestId": response.headers.get("x-request-id"),
            "upstreamActivityId": response.headers.get("activityid"),
        },
    ) from exc


def _extract_consent_request_id(payload: Dict[str, Any]) -> str | None:
    request_id = payload.get("requestId")
    if isinstance(request_id, str) and request_id:
        return request_id

    response = payload.get("response")
    if isinstance(response, dict):
        request_id = response.get("requestId")
        if isinstance(request_id, str) and request_id:
            return request_id
    return None


def _extract_consent_id(payload: Dict[str, Any]) -> str | None:
    consent = payload.get("consent")
    if isinstance(consent, dict) and isinstance(consent.get("id"), str):
        return consent["id"]

    response = payload.get("response")
    if isinstance(response, dict):
        consent = response.get("consent")
        if isinstance(consent, dict) and isinstance(consent.get("id"), str):
            return consent["id"]
    return None


def _extract_transaction_id(payload: Dict[str, Any]) -> str | None:
    transaction_id = payload.get("transactionId")
    if isinstance(transaction_id, str) and transaction_id:
        return transaction_id

    response = payload.get("response")
    if isinstance(response, dict):
        transaction_id = response.get("transactionId")
        if isinstance(transaction_id, str) and transaction_id:
            return transaction_id
    return None
