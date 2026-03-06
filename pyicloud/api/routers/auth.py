"""Auth API routes."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from httpx import ASGITransport, AsyncClient

from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.auth_abuse_guard import AuthAbuseGuardService
from pyicloud.application.operation_suspension import OperationSuspensionService
from pyicloud.domain import (
    ChallengeExpired,
    Conflict,
    Forbidden,
    InvalidChallengeTransition,
    InvalidCredentials,
    InvalidSecurityCode,
    Unauthorized,
)

from ..dependencies import (
    extract_token,
    get_auth_abuse_guard_service,
    get_auth_service,
    get_operation_suspension_service,
)
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
LOGGER = logging.getLogger("pyicloud.audit")


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


async def _resume_suspended_operation(
    *,
    request: Request,
    service: OperationSuspensionService,
    operation_id: str,
    token: str,
) -> tuple[int, dict[str, Any] | None]:
    operation = service.mark_resuming(operation_id=operation_id)
    replay_headers = {
        "Authorization": f"Bearer {token}",
        "X-PYICLOUD-Operation-Resume": operation.operation_id,
    }
    if operation.idempotency_key:
        replay_headers["Idempotency-Key"] = operation.idempotency_key
    if operation.content_type:
        replay_headers["Content-Type"] = operation.content_type
    replay_url = operation.path
    if operation.query_string:
        replay_url = f"{replay_url}?{operation.query_string}"

    try:
        async with AsyncClient(transport=ASGITransport(app=request.app), base_url="http://resume.local") as client:
            response = await client.request(
                method=operation.method,
                url=replay_url,
                headers=replay_headers,
                content=operation.body_text.encode("utf-8") if operation.body_text else None,
            )
    except Exception as err:  # noqa: BLE001
        service.mark_failed(operation_id=operation_id, error=f"Operation replay failed: {err}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "operation_resume_failed",
                "message": "Suspended operation replay failed",
                "operation_id": operation_id,
            },
        ) from err

    try:
        parsed_payload: dict[str, Any] | None = response.json() if response.content else None
    except ValueError:
        parsed_payload = {"raw": response.text}

    error_code = ""
    if isinstance(parsed_payload, dict):
        maybe_error = parsed_payload.get("error")
        if isinstance(maybe_error, dict):
            error_code = str(maybe_error.get("code", ""))
    if response.status_code == status.HTTP_409_CONFLICT and error_code == "operation_resume_failed":
        service.mark_failed(
            operation_id=operation_id,
            error="Operation replay triggered another auth challenge",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "operation_resume_failed",
                "message": "Suspended operation replay requires another auth challenge",
                "operation_id": operation_id,
            },
        )

    service.mark_completed(
        operation_id=operation_id,
        response_status=response.status_code,
        response_payload=parsed_payload,
    )
    return (response.status_code, parsed_payload)


@router.post("/v1/auth/challenge", response_model=DataEnvelope)
async def auth_challenge(
    payload: AuthChallengeRequest,
    request: Request,
    service: AuthApiService = Depends(get_auth_service),
    suspension_service: OperationSuspensionService = Depends(get_operation_suspension_service),
    abuse_guard: AuthAbuseGuardService = Depends(get_auth_abuse_guard_service),
) -> DataEnvelope:
    client_ip = request.client.host if request.client is not None else "unknown"
    try:
        abuse_guard.guard_attempt(
            account_id=payload.username,
            client_ip=client_ip,
            challenge_id=payload.challenge_id,
            session_id=payload.session_id,
        )
    except Forbidden as err:
        LOGGER.info("audit_event type=challenge_rate_limited account_id=%s ip=%s", payload.username or "", client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "auth_rate_limited", "message": str(err)},
        ) from err

    try:
        result = await service.challenge(
            username=payload.username,
            challenge_id=payload.challenge_id,
            session_id=payload.session_id,
            password_envelope=payload.password_envelope,
            security_code=payload.security_code,
        )
        operation_id = str(result.get("operation_id", "")).strip()
        token = str(result.get("access_token", "")).strip()
        if result.get("challenge_type") == "authenticated" and operation_id and token:
            operation_status, operation_result = await _resume_suspended_operation(
                request=request,
                service=suspension_service,
                operation_id=operation_id,
                token=token,
            )
            result["operation_status"] = operation_status
            result["operation_result"] = operation_result
            LOGGER.info(
                "audit_event type=operation_resumed operation_id=%s status=%s",
                operation_id,
                operation_status,
            )
        if result.get("challenge_type") == "authenticated":
            abuse_guard.record_success(
                account_id=str(result.get("account_id", "") or payload.username or ""),
                client_ip=client_ip,
                challenge_id=payload.challenge_id,
                session_id=str(result.get("session_id", "") or payload.session_id or ""),
            )
        LOGGER.info(
            "audit_event type=challenge_completed challenge_type=%s account_id=%s",
            str(result.get("challenge_type", "")),
            str(result.get("account_id", "") or payload.username or ""),
        )
    except Conflict as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err
    except ChallengeExpired as err:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(err)) from err
    except InvalidChallengeTransition as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except InvalidSecurityCode as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except InvalidCredentials as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except Forbidden as err:
        LOGGER.info(
            "audit_event type=allowlist_decision decision=deny account_id=%s",
            payload.username or "",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    return ok(AuthChallengeResponse.model_validate(result))


@router.post("/v1/auth/login", response_model=DataEnvelope)
async def auth_login(
    payload: AuthLoginRequest,
    request: Request,
    service: AuthApiService = Depends(get_auth_service),
    abuse_guard: AuthAbuseGuardService = Depends(get_auth_abuse_guard_service),
) -> DataEnvelope:
    client_ip = request.client.host if request.client is not None else "unknown"
    try:
        abuse_guard.guard_attempt(
            account_id=payload.username,
            client_ip=client_ip,
            session_id=payload.flow_id,
        )
    except Forbidden as err:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "auth_rate_limited", "message": str(err)},
        ) from err
    try:
        challenge_result = await service.challenge(
            username=payload.username,
            password_envelope=payload.password,
            session_id=payload.flow_id,
        )
        result = _to_legacy_login_payload(challenge_result)
        if str(result.get("status", "")) == "authenticated":
            abuse_guard.record_success(
                account_id=payload.username,
                client_ip=client_ip,
                session_id=payload.flow_id,
            )
    except InvalidCredentials as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except InvalidChallengeTransition as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except Forbidden as err:
        LOGGER.info("audit_event type=allowlist_decision decision=deny account_id=%s", payload.username)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    return ok(AuthLoginResponse.model_validate(result))


@router.post("/v1/auth/security-code", response_model=DataEnvelope)
async def auth_security_code(
    payload: AuthSecurityCodeRequest,
    request: Request,
    service: AuthApiService = Depends(get_auth_service),
    abuse_guard: AuthAbuseGuardService = Depends(get_auth_abuse_guard_service),
) -> DataEnvelope:
    client_ip = request.client.host if request.client is not None else "unknown"
    try:
        abuse_guard.guard_attempt(
            account_id=payload.username,
            client_ip=client_ip,
            challenge_id=payload.challenge_id,
        )
    except Forbidden as err:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "auth_rate_limited", "message": str(err)},
        ) from err
    try:
        challenge_result = await service.challenge(
            challenge_id=payload.challenge_id,
            security_code=payload.code,
            password_envelope=payload.password,
            username=payload.username,
        )
        result = _to_legacy_login_payload(challenge_result)
        if str(result.get("status", "")) == "authenticated":
            abuse_guard.record_success(
                account_id=payload.username,
                client_ip=client_ip,
                challenge_id=payload.challenge_id,
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
        LOGGER.info(
            "audit_event type=allowlist_decision decision=deny account_id=%s",
            payload.username or "",
        )
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
