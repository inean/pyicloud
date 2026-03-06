"""FastAPI application factory for the pyicloud API layer."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from pyicloud.adapters.upstream_probe import validate_upstream_probe_configuration
from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.application.observability import ObservabilityApi
from pyicloud.bootstrap import (
    build_default_auth_api_service,
    build_default_core_services_api,
    build_default_observability_api,
)
from pyicloud.domain import (
    BackendUnavailable,
    QueryExecutionFailed,
    UnsupportedQueryMode,
)

from .dependencies import get_core_services, get_observability_service, get_username
from .errors import register_exception_handlers
from .instrumentation import ApiTelemetryMiddleware, telemetry_enabled
from .responses import ok
from .routers import account_router, auth_router, devices_router, drive_router
from .schemas import (
    DataEnvelope,
    ObservabilityQueryRequest,
    ObservabilityQueryResponse,
    PhotoAssetMetadataResponse,
    ReminderCreateRequest,
    SimpleOkResponse,
    UbiquityFileMetadataResponse,
)


def _build_default_auth_service() -> AuthApiService:
    return build_default_auth_api_service()


def _build_default_core_services() -> CoreServicesApi:
    return build_default_core_services_api()


def _build_default_observability_service() -> ObservabilityApi:
    return build_default_observability_api()


def create_app(
    *,
    auth_service: AuthApiService | None = None,
    core_services: CoreServicesApi | None = None,
    observability_service: ObservabilityApi | None = None,
) -> FastAPI:
    """Build and configure the FastAPI application."""
    validate_upstream_probe_configuration()

    app = FastAPI(title="pyicloud API", version="1.0.0")
    if telemetry_enabled():
        app.add_middleware(ApiTelemetryMiddleware)
    app.state.auth_service = auth_service or _build_default_auth_service()
    app.state.core_services = core_services or _build_default_core_services()
    app.state.observability_service = observability_service or _build_default_observability_service()
    register_exception_handlers(app)
    app.include_router(auth_router)
    app.include_router(devices_router)
    app.include_router(account_router)
    app.include_router(drive_router)

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

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/calendar/calendars")
    async def calendar_calendars(
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return ok(await service.calendar_calendars(username=username))

    @app.get("/v1/calendar/events")
    async def calendar_events(
        from_dt: datetime | None = Query(default=None),
        to_dt: datetime | None = Query(default=None),
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return ok(await service.calendar_events(username=username, from_dt=from_dt, to_dt=to_dt))

    @app.get("/v1/calendar/event-detail")
    async def calendar_event_detail(
        calendar_guid: str = Query(..., min_length=1),
        event_guid: str = Query(..., min_length=1),
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return ok(
                await service.calendar_event_detail(
                    username=username,
                    calendar_guid=calendar_guid,
                    event_guid=event_guid,
                )
            )
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/contacts")
    async def contacts_list(
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return ok(await service.contacts_all(username=username))

    @app.get("/v1/reminders")
    async def reminders_list(
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return ok(await service.reminders_lists(username=username))

    @app.post("/v1/reminders", response_model=DataEnvelope)
    async def reminders_create(
        payload: ReminderCreateRequest,
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        created = await service.reminders_create(
            username=username,
            title=payload.title,
            description=payload.description,
            collection=payload.collection,
            due_date=payload.due_date,
        )
        if not created:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Reminder creation failed")
        return ok(SimpleOkResponse(detail="Reminder created"))

    @app.get("/v1/photos/albums")
    async def photos_albums(
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return ok(await service.photos_albums(username=username))

    @app.get("/v1/photos/assets")
    async def photos_assets(
        album: str = Query(default="All Photos"),
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return ok(await service.photos_assets(username=username, album=album, limit=limit, offset=offset))
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/photos/asset", response_model=DataEnvelope)
    async def photos_asset(
        asset_id: str = Query(..., min_length=1),
        album: str = Query(default="All Photos"),
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        try:
            metadata = await service.photo_asset_metadata(username=username, asset_id=asset_id, album=album)
            return ok(PhotoAssetMetadataResponse.model_validate(metadata))
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/photos/download")
    async def photos_download(
        asset_id: str = Query(..., min_length=1),
        album: str = Query(default="All Photos"),
        version: str = Query(default="original", min_length=1),
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> StreamingResponse:
        try:
            metadata = PhotoAssetMetadataResponse.model_validate(
                await service.photo_asset_metadata(username=username, asset_id=asset_id, album=album)
            )
            content = await service.photo_asset_content(
                username=username,
                asset_id=asset_id,
                album=album,
                version=version,
            )
        except ValidationError as err:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Invalid photo metadata: {err}"
            ) from err
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
        filename = metadata.filename.strip() or f"{asset_id}.bin"
        return StreamingResponse(
            iter([content]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/v1/ubiquity/tree")
    async def ubiquity_tree(
        path: str = Query(default="/"),
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return ok(await service.ubiquity_tree(username=username, path=path))
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/ubiquity/file")
    async def ubiquity_file(
        path: str = Query(...),
        download: bool = Query(default=False),
        username: str = Depends(get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            if not download:
                metadata = await service.ubiquity_file_metadata(username=username, path=path)
                return ok(UbiquityFileMetadataResponse.model_validate(metadata))
            metadata = UbiquityFileMetadataResponse.model_validate(
                await service.ubiquity_file_metadata(username=username, path=path)
            )
            content = await service.ubiquity_file_content(username=username, path=path)
        except ValidationError as err:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Invalid ubiquity metadata: {err}"
            ) from err
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

        filename = metadata.name.strip() or "file.bin"
        return StreamingResponse(
            iter([content]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/v1/observability/promql", response_model=DataEnvelope)
    def observability_promql(
        payload: ObservabilityQueryRequest,
        username: str = Depends(get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> DataEnvelope:
        return ok(_run_observability_query(language="promql", payload=payload, service=service))

    @app.post("/v1/observability/traceql", response_model=DataEnvelope)
    def observability_traceql(
        payload: ObservabilityQueryRequest,
        username: str = Depends(get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> DataEnvelope:
        return ok(_run_observability_query(language="traceql", payload=payload, service=service))

    @app.post("/v1/observability/logql", response_model=DataEnvelope)
    def observability_logql(
        payload: ObservabilityQueryRequest,
        username: str = Depends(get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> DataEnvelope:
        return ok(_run_observability_query(language="logql", payload=payload, service=service))

    return app


__all__ = ["create_app"]
