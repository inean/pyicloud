"""FastAPI application factory for the pyicloud API layer."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Path, Query, Request, UploadFile, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from pyicloud.adapters.observability import NullObservabilityAdapter, OTelObservabilityAdapter, ensure_otel_dependencies
from pyicloud.adapters.services import build_legacy_core_adapter_bundle
from pyicloud.adapters.session import FileApiSessionStore, InMemoryApiSessionStore
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
    DataEnvelope,
    DeviceLostModeRequest,
    DeviceMessageRequest,
    DevicePlaySoundRequest,
    DriveCreateFolderRequest,
    DriveFileMetadataResponse,
    DriveRenameNodeRequest,
    ObservabilityQueryRequest,
    ObservabilityQueryResponse,
    PhotoAssetMetadataResponse,
    ReminderCreateRequest,
    SimpleOkResponse,
    UbiquityFileMetadataResponse,
)


def _build_default_auth_service() -> AuthApiService:
    runtime_env = os.getenv("PYICLOUD_API_ENV", os.getenv("PYICLOUD_ENV", "dev")).strip().lower()
    is_non_dev = runtime_env not in {"dev", "development", "local", "test", "testing"}

    secret = os.getenv("PYICLOUD_API_JWT_SECRET", "pyicloud-api-dev-secret")
    if is_non_dev and "PYICLOUD_API_JWT_SECRET" not in os.environ:
        raise RuntimeError("PYICLOUD_API_JWT_SECRET must be explicitly configured in non-dev runtime")

    leeway_seconds_raw = os.getenv("PYICLOUD_API_JWT_LEEWAY_SECONDS", "0")
    try:
        leeway_seconds = int(leeway_seconds_raw)
    except ValueError as err:
        raise RuntimeError("PYICLOUD_API_JWT_LEEWAY_SECONDS must be an integer") from err

    signer = JwtTokenSigner(
        secret=secret,
        leeway_seconds=leeway_seconds,
        enforce_strong_secret=is_non_dev,
    )

    session_backend = os.getenv("PYICLOUD_API_SESSION_BACKEND", "memory").strip().lower()
    if session_backend in {"memory", "in-memory", "inmemory"}:
        session_store = InMemoryApiSessionStore()
    elif session_backend == "file":
        session_store = FileApiSessionStore(root_dir=os.getenv("PYICLOUD_API_SESSION_STORE_DIR"))
    else:
        raise RuntimeError(f"Unsupported auth session backend: {session_backend}")
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

    def _ok(payload: Any) -> dict[str, Any]:
        return {"data": payload}

    def _error_code(status_code: int) -> str:
        mapping = {
            status.HTTP_401_UNAUTHORIZED: "unauthorized",
            status.HTTP_404_NOT_FOUND: "not_found",
            status.HTTP_410_GONE: "expired",
            status.HTTP_422_UNPROCESSABLE_CONTENT: "validation_error",
            status.HTTP_502_BAD_GATEWAY: "upstream_error",
            status.HTTP_503_SERVICE_UNAVAILABLE: "service_unavailable",
        }
        return mapping.get(status_code, "http_error")

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        details: Any | None = None
        message = str(exc.detail)
        if isinstance(exc.detail, dict):
            message = str(exc.detail.get("message", exc.detail))
            details = exc.detail
        payload = {
            "error": {
                "code": _error_code(exc.status_code),
                "message": message,
                "status": exc.status_code,
                "details": details,
            }
        }
        return JSONResponse(status_code=exc.status_code, content=payload)

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        payload = {
            "error": {
                "code": "validation_error",
                "message": "Request validation failed",
                "status": status.HTTP_422_UNPROCESSABLE_CONTENT,
                "details": jsonable_encoder(exc.errors()),
            }
        }
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content=payload)

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
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(err)) from err
        except BackendUnavailable as err:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(err)) from err
        except QueryExecutionFailed as err:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(err)) from err
        return ObservabilityQueryResponse.model_validate(result)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/auth/login", response_model=DataEnvelope)
    async def auth_login(
        payload: AuthLoginRequest,
        service: AuthApiService = Depends(get_auth_service),
    ) -> DataEnvelope:
        try:
            result = await service.login(username=payload.username, password=payload.password)
        except InvalidCredentials as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return _ok(AuthLoginResponse.model_validate(result))

    @app.post("/v1/auth/security-code", response_model=DataEnvelope)
    async def auth_security_code(
        payload: AuthSecurityCodeRequest,
        service: AuthApiService = Depends(get_auth_service),
    ) -> DataEnvelope:
        try:
            result = await service.security_code(challenge_id=payload.challenge_id, code=payload.code)
        except ChallengeExpired as err:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(err)) from err
        except InvalidSecurityCode as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        except InvalidCredentials as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return _ok(AuthLoginResponse.model_validate(result))

    @app.get("/v1/auth/session", response_model=DataEnvelope)
    def auth_session(
        token: str = Depends(_extract_token),
        service: AuthApiService = Depends(get_auth_service),
    ) -> DataEnvelope:
        try:
            principal = service.session(token=token)
        except Unauthorized as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return _ok(
            AuthSessionResponse(
                username=principal.username,
                token_id=principal.token_id,
                expires_at=principal.expires_at,
            )
        )

    @app.post("/v1/auth/logout", response_model=DataEnvelope)
    def auth_logout(
        token: str = Depends(_extract_token),
        service: AuthApiService = Depends(get_auth_service),
    ) -> DataEnvelope:
        try:
            service.logout(token=token)
        except Unauthorized as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return _ok(SimpleOkResponse(detail="Logged out"))

    @app.get("/v1/devices")
    def devices_list(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.list_devices(username=username))

    @app.get("/v1/devices/{device_id}/location")
    def devices_location(
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return _ok(service.device_location(username=username, device_id=device_id))
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/devices/{device_id}/status")
    def devices_status(
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return _ok(service.device_status(username=username, device_id=device_id))
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.post("/v1/devices/{device_id}/actions/play-sound", response_model=DataEnvelope)
    def devices_play_sound(
        payload: DevicePlaySoundRequest,
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        try:
            service.device_play_sound(username=username, device_id=device_id, subject=payload.subject)
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
        return _ok(SimpleOkResponse(detail="Sound command sent"))

    @app.post("/v1/devices/{device_id}/actions/message", response_model=DataEnvelope)
    def devices_message(
        payload: DeviceMessageRequest,
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
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
        return _ok(SimpleOkResponse(detail="Message command sent"))

    @app.post("/v1/devices/{device_id}/actions/lost-mode", response_model=DataEnvelope)
    def devices_lost_mode(
        payload: DeviceLostModeRequest,
        device_id: str = Path(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
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
        return _ok(SimpleOkResponse(detail="Lost mode command sent"))

    @app.get("/v1/account/devices")
    def account_devices(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.account_devices(username=username))

    @app.get("/v1/account/family")
    def account_family(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.account_family(username=username))

    @app.get("/v1/account/storage", response_model=DataEnvelope)
    def account_storage(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        return _ok(AccountStorageResponse.model_validate(service.account_storage(username=username)))

    @app.get("/v1/calendar/calendars")
    def calendar_calendars(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.calendar_calendars(username=username))

    @app.get("/v1/calendar/events")
    def calendar_events(
        from_dt: datetime | None = Query(default=None),
        to_dt: datetime | None = Query(default=None),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.calendar_events(username=username, from_dt=from_dt, to_dt=to_dt))

    @app.get("/v1/calendar/event-detail")
    def calendar_event_detail(
        calendar_guid: str = Query(..., min_length=1),
        event_guid: str = Query(..., min_length=1),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return _ok(
                service.calendar_event_detail(
                    username=username,
                    calendar_guid=calendar_guid,
                    event_guid=event_guid,
                )
            )
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/contacts")
    def contacts_list(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.contacts_all(username=username))

    @app.get("/v1/reminders")
    def reminders_list(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.reminders_lists(username=username))

    @app.post("/v1/reminders", response_model=DataEnvelope)
    def reminders_create(
        payload: ReminderCreateRequest,
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        created = service.reminders_create(
            username=username,
            title=payload.title,
            description=payload.description,
            collection=payload.collection,
            due_date=payload.due_date,
        )
        if not created:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Reminder creation failed")
        return _ok(SimpleOkResponse(detail="Reminder created"))

    @app.get("/v1/photos/albums")
    def photos_albums(
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.photos_albums(username=username))

    @app.get("/v1/photos/assets")
    def photos_assets(
        album: str = Query(default="All Photos"),
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return _ok(service.photos_assets(username=username, album=album, limit=limit, offset=offset))
        except KeyError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    @app.get("/v1/photos/asset", response_model=DataEnvelope)
    def photos_asset(
        asset_id: str = Query(..., min_length=1),
        album: str = Query(default="All Photos"),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        try:
            metadata = service.photo_asset_metadata(username=username, asset_id=asset_id, album=album)
            return _ok(PhotoAssetMetadataResponse.model_validate(metadata))
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
            metadata = PhotoAssetMetadataResponse.model_validate(
                service.photo_asset_metadata(username=username, asset_id=asset_id, album=album)
            )
            content = service.photo_asset_content(
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
    def ubiquity_tree(
        path: str = Query(default="/"),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        try:
            return _ok(service.ubiquity_tree(username=username, path=path))
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
                metadata = service.ubiquity_file_metadata(username=username, path=path)
                return _ok(UbiquityFileMetadataResponse.model_validate(metadata))
            metadata = UbiquityFileMetadataResponse.model_validate(
                service.ubiquity_file_metadata(username=username, path=path)
            )
            content = service.ubiquity_file_content(username=username, path=path)
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
        username: str = Depends(_get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> DataEnvelope:
        return _ok(_run_observability_query(language="promql", payload=payload, service=service))

    @app.post("/v1/observability/traceql", response_model=DataEnvelope)
    def observability_traceql(
        payload: ObservabilityQueryRequest,
        username: str = Depends(_get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> DataEnvelope:
        return _ok(_run_observability_query(language="traceql", payload=payload, service=service))

    @app.post("/v1/observability/logql", response_model=DataEnvelope)
    def observability_logql(
        payload: ObservabilityQueryRequest,
        username: str = Depends(_get_username),  # noqa: ARG001
        service: ObservabilityApi = Depends(get_observability_service),
    ) -> DataEnvelope:
        return _ok(_run_observability_query(language="logql", payload=payload, service=service))

    @app.get("/v1/drive/tree")
    def drive_tree(
        path: str = Query(default="/"),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        return _ok(service.drive_tree(username=username, path=path))

    @app.get("/v1/drive/file")
    def drive_file(
        path: str = Query(...),
        download: bool = Query(default=False),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> Any:
        if not download:
            metadata = service.drive_file_metadata(username=username, path=path)
            return _ok(DriveFileMetadataResponse.model_validate(metadata))

        try:
            metadata = DriveFileMetadataResponse.model_validate(
                service.drive_file_metadata(username=username, path=path)
            )
        except ValidationError as err:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Invalid drive metadata: {err}"
            ) from err
        content = service.drive_file_content(username=username, path=path)
        filename = metadata.name.strip() or "file.bin"
        return StreamingResponse(
            iter([content]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/v1/drive/folders", response_model=DataEnvelope)
    def drive_folders(
        payload: DriveCreateFolderRequest,
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        service.drive_create_folder(username=username, parent_path=payload.parent_path, name=payload.name)
        return _ok(SimpleOkResponse(detail="Folder created"))

    @app.post("/v1/drive/upload", response_model=DataEnvelope)
    async def drive_upload(
        file: UploadFile = File(...),
        parent_path: str = Query(default="/"),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        content = await file.read()
        service.drive_upload_file(
            username=username,
            parent_path=parent_path,
            filename=file.filename or "upload.bin",
            content=content,
        )
        return _ok(SimpleOkResponse(detail="File uploaded"))

    @app.patch("/v1/drive/node", response_model=DataEnvelope)
    def drive_rename(
        payload: DriveRenameNodeRequest,
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        service.drive_rename_node(username=username, path=payload.path, new_name=payload.new_name)
        return _ok(SimpleOkResponse(detail="Node renamed"))

    @app.delete("/v1/drive/node", response_model=DataEnvelope)
    def drive_delete(
        path: str = Query(...),
        username: str = Depends(_get_username),
        service: CoreServicesApi = Depends(get_core_services),
    ) -> DataEnvelope:
        service.drive_delete_node(username=username, path=path)
        return _ok(SimpleOkResponse(detail="Node deleted"))

    return app


__all__ = ["create_app"]
