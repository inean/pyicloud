"""Auth API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from pyicloud.application.api_auth import AuthApiService
from pyicloud.domain import ChallengeExpired, Forbidden, InvalidCredentials, InvalidSecurityCode, Unauthorized

from ..dependencies import extract_token, get_auth_service
from ..responses import ok
from ..schemas import (
    AuthLoginRequest,
    AuthLoginResponse,
    AuthSecurityCodeRequest,
    AuthSessionResponse,
    DataEnvelope,
    SimpleOkResponse,
)

router = APIRouter()


@router.post("/v1/auth/login", response_model=DataEnvelope)
async def auth_login(
    payload: AuthLoginRequest,
    service: AuthApiService = Depends(get_auth_service),
) -> DataEnvelope:
    try:
        result = await service.login(
            username=payload.username,
            password=payload.password,
            flow_id=payload.flow_id,
        )
    except InvalidCredentials as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except Forbidden as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    return ok(AuthLoginResponse.model_validate(result))


@router.post("/v1/auth/security-code", response_model=DataEnvelope)
async def auth_security_code(
    payload: AuthSecurityCodeRequest,
    service: AuthApiService = Depends(get_auth_service),
) -> DataEnvelope:
    try:
        result = await service.security_code(
            challenge_id=payload.challenge_id,
            code=payload.code,
            password=payload.password,
            username=payload.username,
        )
    except ChallengeExpired as err:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(err)) from err
    except InvalidSecurityCode as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except InvalidCredentials as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except Forbidden as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    return ok(AuthLoginResponse.model_validate(result))


@router.get("/v1/auth/session", response_model=DataEnvelope)
def auth_session(
    token: str = Depends(extract_token),
    service: AuthApiService = Depends(get_auth_service),
) -> DataEnvelope:
    try:
        principal = service.session(token=token)
    except Unauthorized as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    return ok(
        AuthSessionResponse(
            username=principal.username,
            token_id=principal.token_id,
            expires_at=principal.expires_at,
        )
    )


@router.post("/v1/auth/logout", response_model=DataEnvelope)
def auth_logout(
    token: str = Depends(extract_token),
    service: AuthApiService = Depends(get_auth_service),
) -> DataEnvelope:
    try:
        service.logout(token=token)
    except Unauthorized as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    return ok(SimpleOkResponse(detail="Logged out"))
