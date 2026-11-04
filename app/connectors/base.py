"""Connector abstractions for national health-network adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class PatientSearchInput:
    """Unified request input for connector-level patient search."""

    patient_id: str | None
    consent_id: str | None
    purpose: str
    date_from: str | None
    date_to: str | None
    data_push_url: str | None


@dataclass
class ConnectorRuntimeContext:
    """Runtime metadata propagated to connectors."""

    correlation_id: str
    region: str | None
    network: str


@dataclass
class ConnectorResult:
    """Normalized connector output before gateway envelope wrapping."""

    status: str
    data: Dict[str, Any]
    upstream: Dict[str, Any]


class BaseHealthConnector(ABC):
    """Abstract adapter interface for a national healthcare ecosystem."""

    @abstractmethod
    async def patient_search(
        self,
        request_data: PatientSearchInput,
        runtime: ConnectorRuntimeContext,
    ) -> ConnectorResult:
        """Execute patient search/retrieval in the target network."""

