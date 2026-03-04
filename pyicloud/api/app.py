"""FastAPI application factory for the pyicloud API layer."""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Path, Query, UploadFile, status
from fastapi.responses import StreamingResponse

from pyicloud.adapters.services import LegacyCoreServicesAdapter
from pyicloud.adapters.session import InMemoryApiSessionStore
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.domain import ChallengeExpired, InvalidCredentials, InvalidSecurityCode, Unauthorized

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
    adapter = LegacyCoreServicesAdapter()
    return CoreServicesApi(devices=adapter, accounts=adapter, drive=adapter)


def create_app(
    *,
    auth_service: AuthApiService | None = None,
    core_services: CoreServicesApi | None = None,
) -> FastAPI:
    """Build and configure the FastAPI application."""

    app = FastAPI(title="pyicloud API", version="1.0.0")
    app.state.auth_service = auth_service or _build_default_auth_service()
    app.state.core_services = core_services or _build_default_core_services()

    def get_auth_service() -> AuthApiService:
        return app.state.auth_service

    def get_core_services() -> CoreServicesApi:
        return app.state.core_services

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
