"""Observability API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from pyicloud.application.observability import ObservabilityApi
from pyicloud.domain import BackendUnavailable, QueryExecutionFailed, UnsupportedQueryMode

from ..dependencies import get_observability_service, get_username
from ..responses import ok
from ..schemas import DataEnvelope, ObservabilityQueryRequest, ObservabilityQueryResponse

router = APIRouter()


def _run_observability_query(
    *,
    language: str,
    payload: ObservabilityQueryRequest,
    service: ObservabilityApi,
) -> ObservabilityQueryResponse:
    try:
        if payload.start is None:
            result = service.instant_query(
                language=language,
                query=payload.query,
                source=payload.source,
            )
        else:
            assert payload.end is not None
            assert payload.step is not None
            result = service.range_query(
                language=language,
                query=payload.query,
                start=payload.start,
                end=payload.end,
                step=payload.step,
                source=payload.source,
            )
    except UnsupportedQueryMode as err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(err)) from err
    except BackendUnavailable as err:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(err)) from err
    except QueryExecutionFailed as err:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(err)) from err
    return ObservabilityQueryResponse.model_validate(result)


@router.post("/v1/observability/promql", response_model=DataEnvelope)
def observability_promql(
    payload: ObservabilityQueryRequest,
    username: str = Depends(get_username),  # noqa: ARG001
    service: ObservabilityApi = Depends(get_observability_service),
) -> DataEnvelope:
    return ok(_run_observability_query(language="promql", payload=payload, service=service))


@router.post("/v1/observability/traceql", response_model=DataEnvelope)
def observability_traceql(
    payload: ObservabilityQueryRequest,
    username: str = Depends(get_username),  # noqa: ARG001
    service: ObservabilityApi = Depends(get_observability_service),
) -> DataEnvelope:
    return ok(_run_observability_query(language="traceql", payload=payload, service=service))


@router.post("/v1/observability/logql", response_model=DataEnvelope)
def observability_logql(
    payload: ObservabilityQueryRequest,
    username: str = Depends(get_username),  # noqa: ARG001
    service: ObservabilityApi = Depends(get_observability_service),
) -> DataEnvelope:
    return ok(_run_observability_query(language="logql", payload=payload, service=service))
