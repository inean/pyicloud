"""FastAPI application factory for the pyicloud API layer."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Path, Query, UploadFile, status
from fastapi.responses import StreamingResponse

from pyicloud.adapters.observability import NullObservabilityAdapter, OTelObservabilityAdapter, ensure_otel_dependencies
from pyicloud.adapters.services import build_legacy_core_adapter_bundle
from pyicloud.adapters.session import InMemoryApiSessionStore
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.application.observability import ObservabilityApi
from pyicloud.domain import (
    BackendUnavailable,
    ChallengeExpired,
    InvalidCredentials,
    InvalidSecurityCode,
    QueryExecutionFailed,
    Unauthorized,
    UnsupportedQueryMode,
)

from .schemas import (
    AccountStorageResponse,
    AuthLoginRequest,
    AuthLoginResponse,
    AuthSecurityCodeRequest,
    AuthSessionResponse,
    DeviceLostModeRequest,
    DeviceMessageRequest,
    DevicePlaySoundRequest,
    DriveCreateFolderRequest,
    DriveRenameNodeRequest,
    ObservabilityQueryRequest,
    ObservabilityQueryResponse,
    ReminderCreateRequest,
    SimpleOkResponse,
)


def _build_default_auth_service() -> AuthApiService:
    secret = os.getenv("PYICLOUD_API_JWT_SECRET", "pyicloud-api-dev-secret")
    signer = JwtTokenSigner(secret=secret)
    session_store = InMemoryApiSessionStore()
    store_dir = os.getenv("PYICLOUD_SESSION_STORE_DIR")
    return AuthApiService(
        token_signer=signer,
        session_query=session_store,
        session_command=session_store,
        store_dir=store_dir,
    )


def _build_default_core_services() -> CoreServicesApi:
    adapters = build_legacy_core_adapter_bundle()
    return CoreServicesApi(
        devices=adapters.devices,
        accounts=adapters.accounts,
        drive=adapters.drive,
        calendars=adapters.calendars,
        contacts=adapters.contacts,
        reminders=adapters.reminders,
        photos=adapters.photos,
        ubiquity=adapters.ubiquity,
    )


def _build_default_observability_service() -> ObservabilityApi:
    adapter_name = os.getenv("PYICLOUD_OBSERVABILITY_ADAPTER", "null").strip().lower()
    if adapter_name == "null":
        adapter = NullObservabilityAdapter()
        return ObservabilityApi(promql=adapter, traceql=adapter, logql=adapter)
    if adapter_name == "otel":
        ensure_otel_dependencies()
        timeout_raw = os.getenv("PYICLOUD_OBSERVABILITY_TIMEOUT_SECONDS", "10.0")
        try:
            timeout_seconds = float(timeout_raw)
        except ValueError as err:
            raise RuntimeError("PYICLOUD_OBSERVABILITY_TIMEOUT_SECONDS must be numeric") from err
        adapter = OTelObservabilityAdapter(
            promql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_PROMQL_ENDPOINT"),
            traceql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_TRACEQL_ENDPOINT"),
            logql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_LOGQL_ENDPOINT"),
            timeout_seconds=timeout_seconds,
        )
        return ObservabilityApi(promql=adapter, traceql=adapter, logql=adapter)
    raise RuntimeError(f"Unsupported observability adapter: {adapter_name}")


def create_app(
    *,
    auth_service: AuthApiService | None = None,
    core_services: CoreServicesApi | None = None,
    observability_service: ObservabilityApi | None = None,
) -> FastAPI:
    """Build and configure the FastAPI application."""

    app = FastAPI(title="pyicloud API", version="1.0.0")
    app.state.auth_service = auth_service or _build_default_auth_service()
    app.state.core_services = core_services or _build_default_core_services()
    app.state.observability_service = observability_service or _build_default_observability_service()

    def get_auth_service() -> AuthApiService:
        return app.state.auth_service

    def get_core_services() -> CoreServicesApi:
        return app.state.core_services

    def get_observability_service() -> ObservabilityApi:
        return app.state.observability_service

    def _extract_token(authorization: str | None = Header(default=None)) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
        return authorization.split(" ", 1)[1].strip()

    def _get_username(
        token: str = Depends(_extract_token),
        service: AuthApiService = Depends(get_auth_service),
    ) -> str:
        try:
            principal = service.session(token=token)
        except Unauthorized as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return principal.username

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
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)) from err
        except BackendUnavailable as err:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(err)) from err
        except QueryExecutionFailed as err:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(err)) from err
        return ObservabilityQueryResponse.model_validate(result)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/auth/login", response_model=AuthLoginResponse)
    async def auth_login(
        payload: AuthLoginRequest,
        service: AuthApiService = Depends(get_auth_service),
    ) -> AuthLoginResponse:
        try:
            result = await service.login(username=payload.username, password=payload.password)
        except InvalidCredentials as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return AuthLoginResponse.model_validate(result)

    @app.post("/v1/auth/security-code", response_model=AuthLoginResponse)
    async def auth_security_code(
        payload: AuthSecurityCodeRequest,
        service: AuthApiService = Depends(get_auth_service),
    ) -> AuthLoginResponse:
        try:
            result = await service.security_code(challenge_id=payload.challenge_id, code=payload.code)
        except ChallengeExpired as err:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(err)) from err
        except InvalidSecurityCode as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        except InvalidCredentials as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return AuthLoginResponse.model_validate(result)

    @app.get("/v1/auth/session", response_model=AuthSessionResponse)
    def auth_session(
        token: str = Depends(_extract_token),
        service: AuthApiService = Depends(get_auth_service),
    ) -> AuthSessionResponse:
        try:
            principal = service.session(token=token)
        except Unauthorized as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return AuthSessionResponse(
            username=principal.username,
            token_id=principal.token_id,
            expires_at=principal.expires_at,
        )

    @app.post("/v1/auth/logout", response_model=SimpleOkResponse)
    def auth_logout(
        token: str = Depends(_extract_token),
        service: AuthApiService = Depends(get_auth_service),
    ) -> SimpleOkResponse:
        try:
            service.logout(token=token)
        except Unauthorized as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return SimpleOkResponse(detail="Logged out")

    @app.get("/v1/devices")
    def devices_list(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.list_devices(username=username)

    @app.get("/v1/devices/{device_id}/location")
    def devices_location(
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return service.device_location(username=username, device_id=device_id)
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/devices/{device_id}/status")
    def devices_status(
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return service.device_status(username=username, device_id=device_id)
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.post("/v1/devices/{device_id}/actions/play-sound", response_model=SimpleOkResponse)
    def devices_play_sound(
        payload: DevicePlaySoundRequest,
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> SimpleOkResponse:
        try:
            service.device_play_sound(username=username, device_id=device_id, subject=payload.subject)
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
        return SimpleOkResponse(detail="Sound command sent")

    @app.post("/v1/devices/{device_id}/actions/message", response_model=SimpleOkResponse)
    def devices_message(
        payload: DeviceMessageRequest,
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> SimpleOkResponse:
        try:
            service.device_message(
                username=username,
                device_id=device_id,
                subject=payload.subject,
                message=payload.message,
                sounds=payload.sounds,
            )
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
        return SimpleOkResponse(detail="Message command sent")

    @app.post("/v1/devices/{device_id}/actions/lost-mode", response_model=SimpleOkResponse)
    def devices_lost_mode(
        payload: DeviceLostModeRequest,
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> SimpleOkResponse:
        try:
            service.device_lost_mode(
                username=username,
                device_id=device_id,
                number=payload.number,
                text=payload.text,
                newpasscode=payload.newpasscode,
            )
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
        return SimpleOkResponse(detail="Lost mode command sent")

    @app.get("/v1/account/devices")
    def account_devices(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.account_devices(username=username)

    @app.get("/v1/account/family")
    def account_family(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.account_family(username=username)

    @app.get("/v1/account/storage", response_model=AccountStorageResponse)
    def account_storage(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> AccountStorageResponse:
        return AccountStorageResponse.model_validate(service.account_storage(username=username))

    @app.get("/v1/calendar/calendars")
    def calendar_calendars(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.calendar_calendars(username=username)

    @app.get("/v1/calendar/events")
    def calendar_events(
        from_dt: datetime | None = Query(default=None),
        to_dt: datetime | None = Query(default=None),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.calendar_events(username=username, from_dt=from_dt, to_dt=to_dt)

    @app.get("/v1/calendar/event-detail")
    def calendar_event_detail(
        calendar_guid: str = Query(..., min_length=1),
        event_guid: str = Query(..., min_length=1),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return service.calendar_event_detail(
                username=username,
                calendar_guid=calendar_guid,
                event_guid=event_guid,
            )
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/contacts")
    def contacts_list(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.contacts_all(username=username)

    @app.get("/v1/reminders")
    def reminders_list(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.reminders_lists(username=username)

    @app.post("/v1/reminders", response_model=SimpleOkResponse)
    def reminders_create(
        payload: ReminderCreateRequest,
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> SimpleOkResponse:
        created = service.reminders_create(
            username=username,
            title=payload.title,
            description=payload.description,
            collection=payload.collection,
            due_date=payload.due_date,
        )
        if not created:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Reminder creation failed")
        return SimpleOkResponse(detail="Reminder created")

    @app.get("/v1/photos/albums")
    def photos_albums(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.photos_albums(username=username)

    @app.get("/v1/photos/assets")
    def photos_assets(
        album: str = Query(default="All Photos"),
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return service.photos_assets(username=username, album=album, limit=limit, offset=offset)
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/photos/asset")
    def photos_asset(
        asset_id: str = Query(..., min_length=1),
        album: str = Query(default="All Photos"),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return service.photo_asset_metadata(username=username, asset_id=asset_id, album=album)
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/photos/download")
    def photos_download(
        asset_id: str = Query(..., min_length=1),
        album: str = Query(default="All Photos"),
        version: str = Query(default="original", min_length=1),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> StreamingResponse:
        try:
            metadata = service.photo_asset_metadata(username=username, asset_id=asset_id, album=album)
            content = service.photo_asset_content(
                username=username,
                asset_id=asset_id,
                album=album,
                version=version,
            )
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
        filename = str(metadata.get("filename") or f"{asset_id}.bin")
        return StreamingResponse(
            iter([content]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/v1/ubiquity/tree")
    def ubiquity_tree(
        path: str = Query(default="/"),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return service.ubiquity_tree(username=username, path=path)
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/ubiquity/file")
    def ubiquity_file(
        path: str = Query(...),
        download: bool = Query(default=False),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            if not download:
                return service.ubiquity_file_metadata(username=username, path=path)
            content = service.ubiquity_file_content(username=username, path=path)
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

        filename = path.strip("/").split("/")[-1] or "file.bin"
        return StreamingResponse(
            iter([content]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/v1/observability/promql", response_model=ObservabilityQueryResponse)
    def observability_promql(
        payload: ObservabilityQueryRequest,
        username: str = Depends(_get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> ObservabilityQueryResponse:
        return _run_observability_query(language="promql", payload=payload, service=service)

    @app.post("/v1/observability/traceql", response_model=ObservabilityQueryResponse)
    def observability_traceql(
        payload: ObservabilityQueryRequest,
        username: str = Depends(_get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> ObservabilityQueryResponse:
        return _run_observability_query(language="traceql", payload=payload, service=service)

    @app.post("/v1/observability/logql", response_model=ObservabilityQueryResponse)
    def observability_logql(
        payload: ObservabilityQueryRequest,
        username: str = Depends(_get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> ObservabilityQueryResponse:
        return _run_observability_query(language="logql", payload=payload, service=service)

    @app.get("/v1/drive/tree")
    def drive_tree(
        path: str = Query(default="/"),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return service.drive_tree(username=username, path=path)

    @app.get("/v1/drive/file")
    def drive_file(
        path: str = Query(...),
        download: bool = Query(default=False),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        if not download:
            return service.drive_file_metadata(username=username, path=path)

        content = service.drive_file_content(username=username, path=path)
        filename = path.strip("/").split("/")[-1] or "file.bin"
        return StreamingResponse(
            iter([content]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/v1/drive/folders", response_model=SimpleOkResponse)
    def drive_folders(
        payload: DriveCreateFolderRequest,
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> SimpleOkResponse:
        service.drive_create_folder(username=username, parent_path=payload.parent_path, name=payload.name)
        return SimpleOkResponse(detail="Folder created")

    @app.post("/v1/drive/upload", response_model=SimpleOkResponse)
    async def drive_upload(
        file: UploadFile = File(...),
        parent_path: str = Query(default="/"),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> SimpleOkResponse:
        content = await file.read()
        service.drive_upload_file(
            username=username,
            parent_path=parent_path,
            filename=file.filename or "upload.bin",
            content=content,
        )
        return SimpleOkResponse(detail="File uploaded")

    @app.patch("/v1/drive/node", response_model=SimpleOkResponse)
    def drive_rename(
        payload: DriveRenameNodeRequest,
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> SimpleOkResponse:
        service.drive_rename_node(username=username, path=payload.path, new_name=payload.new_name)
        return SimpleOkResponse(detail="Node renamed")

    @app.delete("/v1/drive/node", response_model=SimpleOkResponse)
    def drive_delete(
        path: str = Query(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> SimpleOkResponse:
        service.drive_delete_node(username=username, path=path)
        return SimpleOkResponse(detail="Node deleted")

    return app


__all__ = ["create_app"]
