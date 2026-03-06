"""Auth API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from pyicloud.application.api_auth import AuthApiService
from pyicloud.domain import (
    ChallengeExpired,
    Forbidden,
    InvalidChallengeTransition,
    InvalidCredentials,
    InvalidSecurityCode,
    Unauthorized,
)

from ..dependencies import extract_token, get_auth_service
from ..responses import ok
from ..schemas import (
    AuthChallengeRequest,
    AuthChallengeResponse,
    AuthLoginRequest,
    AuthLoginResponse,
    AuthSecurityCodeRequest,
    AuthSessionResponse,
    DataEnvelope,
    SimpleOkResponse,
)

router = APIRouter()


def _to_legacy_login_payload(challenge_payload: dict[str, object]) -> dict[str, object]:
    challenge_type = str(challenge_payload.get("challenge_type", ""))
    if challenge_type == "authenticated":
        return {
            "status": "authenticated",
            "access_token": challenge_payload.get("access_token"),
            "token_type": challenge_payload.get("token_type"),
            "expires_in": challenge_payload.get("expires_in"),
            "flow_id": challenge_payload.get("session_id"),
            "expires_at": challenge_payload.get("expires_at"),
        }
    if challenge_type == "security_code_required":
        return {
            "status": "challenge_required",
            "challenge_id": challenge_payload.get("challenge_id"),
            "flow_id": challenge_payload.get("session_id"),
            "challenge_type": "security_code",
            "account_id": challenge_payload.get("account_id"),
            "expires_at": challenge_payload.get("expires_at"),
            "next_step": "auth.security_code",
            "retryable": challenge_payload.get("retryable"),
        }
    if challenge_type == "password_required":
        return {
            "status": "challenge_required",
            "challenge_id": challenge_payload.get("challenge_id"),
            "flow_id": challenge_payload.get("session_id"),
            "challenge_type": "password",
            "account_id": challenge_payload.get("account_id"),
            "expires_at": challenge_payload.get("expires_at"),
            "next_step": "auth.login",
            "retryable": challenge_payload.get("retryable"),
        }
    if challenge_type == "operation_resume_required":
        return {
            "status": "challenge_required",
            "challenge_id": challenge_payload.get("challenge_id"),
            "flow_id": challenge_payload.get("session_id"),
            "challenge_type": "session_refresh",
            "account_id": challenge_payload.get("account_id"),
            "expires_at": challenge_payload.get("expires_at"),
            "next_step": "auth.login",
            "retryable": challenge_payload.get("retryable"),
        }
    raise InvalidChallengeTransition(f"Unsupported challenge payload: {challenge_type or 'unknown'}")


@router.post("/v1/auth/challenge", response_model=DataEnvelope)
async def auth_challenge(
    payload: AuthChallengeRequest,
    service: AuthApiService = Depends(get_auth_service),
) -> DataEnvelope:
    try:
        result = await service.challenge(
            username=payload.username,
            challenge_id=payload.challenge_id,
            password_envelope=payload.password_envelope,
            security_code=payload.security_code,
        )
    except ChallengeExpired as err:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(err)) from err
    except InvalidChallengeTransition as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except InvalidSecurityCode as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except InvalidCredentials as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except Forbidden as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    return ok(AuthChallengeResponse.model_validate(result))


@router.post("/v1/auth/login", response_model=DataEnvelope)
async def auth_login(
    payload: AuthLoginRequest,
    service: AuthApiService = Depends(get_auth_service),
) -> DataEnvelope:
    try:
        challenge_result = await service.challenge(
            username=payload.username,
            password_envelope=payload.password,
            session_id=payload.flow_id,
        )
        result = _to_legacy_login_payload(challenge_result)
    except InvalidCredentials as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except InvalidChallengeTransition as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except Forbidden as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    return ok(AuthLoginResponse.model_validate(result))


@router.post("/v1/auth/security-code", response_model=DataEnvelope)
async def auth_security_code(
    payload: AuthSecurityCodeRequest,
    service: AuthApiService = Depends(get_auth_service),
) -> DataEnvelope:
    try:
        challenge_result = await service.challenge(
            challenge_id=payload.challenge_id,
            security_code=payload.code,
            password_envelope=payload.password,
            username=payload.username,
        )
        result = _to_legacy_login_payload(challenge_result)
    except ChallengeExpired as err:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(err)) from err
    except InvalidChallengeTransition as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
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
