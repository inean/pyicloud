"""Exception mapping for API error envelopes."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from pyicloud.domain import Unauthorized
from pyicloud.exceptions import PyiCloudAPIResponseError

LOGGER = logging.getLogger("pyicloud.audit")


def _error_code(status_code: int) -> str:
    mapping = {
        status.HTTP_401_UNAUTHORIZED: "unauthorized",
        status.HTTP_403_FORBIDDEN: "forbidden",
        status.HTTP_404_NOT_FOUND: "not_found",
        status.HTTP_410_GONE: "expired",
        status.HTTP_422_UNPROCESSABLE_CONTENT: "validation_error",
        status.HTTP_502_BAD_GATEWAY: "upstream_error",
        status.HTTP_503_SERVICE_UNAVAILABLE: "service_unavailable",
    }
    return mapping.get(status_code, "http_error")


def _coerce_upstream_status(raw_code: str | int | None) -> int | None:
    if raw_code is None:
        return None
    if isinstance(raw_code, int):
        return raw_code
    try:
        return int(raw_code)
    except (TypeError, ValueError):
        return None


def register_exception_handlers(app: FastAPI) -> None:
    """Register deterministic exception -> envelope mappings."""

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        details: Any | None = None
        message = str(exc.detail)
        explicit_code: str | None = None
        if isinstance(exc.detail, dict):
            maybe_code = exc.detail.get("code")
            if isinstance(maybe_code, str) and maybe_code.strip():
                explicit_code = maybe_code.strip()
            message = str(exc.detail.get("message", exc.detail))
            details = exc.detail
        payload = {
            "error": {
                "code": explicit_code or _error_code(exc.status_code),
                "message": message,
                "status": exc.status_code,
                "details": details,
            }
        }
        return JSONResponse(status_code=exc.status_code, content=payload)

    @app.exception_handler(PyiCloudAPIResponseError)
    async def _pyicloud_api_error_handler(request: Request, exc: PyiCloudAPIResponseError) -> JSONResponse:
        upstream_status = _coerce_upstream_status(exc.code)
        if upstream_status in {401, 421, 450}:
            resume_operation_id = request.headers.get("x-pyicloud-operation-resume", "").strip()
            if resume_operation_id:
                LOGGER.info("audit_event type=operation_resume_failed operation_id=%s", resume_operation_id)
                return await _http_exception_handler(
                    request,
                    HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail={
                            "code": "operation_resume_failed",
                            "message": "Operation resume requires another auth challenge and was aborted",
                            "operation_id": resume_operation_id,
                        },
                    ),
                )
            authorization = request.headers.get("authorization", "")
            token = authorization.split(" ", 1)[1].strip() if authorization.startswith("Bearer ") else ""
            principal = None
            if token:
                try:
                    principal = request.app.state.auth_service.session(token=token)
                except Unauthorized:
                    principal = None
            if principal is not None:
                mutating_method = request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
                idempotency_key = request.headers.get("idempotency-key")
                if mutating_method and not idempotency_key:
                    LOGGER.info(
                        "audit_event type=idempotency_key_required method=%s path=%s",
                        request.method,
                        request.url.path,
                    )
                    return await _http_exception_handler(
                        request,
                        HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail={
                                "code": "idempotency_key_required",
                                "message": "Idempotency-Key header is required for mutating operation suspension",
                            },
                        ),
                    )
                body = await request.body()
                body_text = body.decode("utf-8", errors="replace") if body else None
                operation = request.app.state.operation_suspension_service.suspend_operation(
                    account_id=principal.username,
                    method=request.method,
                    path=request.url.path,
                    query_string=request.url.query,
                    body_text=body_text,
                    content_type=request.headers.get("content-type"),
                    idempotency_key=idempotency_key,
                )
                challenge = request.app.state.auth_service.issue_operation_challenge(
                    account_id=principal.username,
                    upstream_status=upstream_status,
                    operation=f"{request.method} {request.url.path}",
                    reason=str(exc.reason or ""),
                    operation_id=operation.operation_id,
                )
                request.app.state.operation_suspension_service.attach_challenge(
                    operation_id=operation.operation_id,
                    challenge_id=str(challenge["challenge_id"]),
                )
                LOGGER.info(
                    "audit_event type=challenge_issued challenge_type=session_refresh account_id=%s operation_id=%s",
                    principal.username,
                    operation.operation_id,
                )
                return await _http_exception_handler(
                    request,
                    HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail={
                            "code": "auth_challenge_required",
                            "message": "Apple session expired or requires re-authentication",
                            **challenge,
                        },
                    ),
                )
        detail_payload: dict[str, Any] = {
            "message": str(exc.reason or "Upstream iCloud request failed"),
            "upstream_status": upstream_status,
            "upstream_reason": str(exc.reason or ""),
            "retryable": upstream_status in {421, 450, 500},
        }
        if upstream_status in {421, 450}:
            detail_payload["hint"] = "Run `icloud auth login` again to refresh the Apple upstream session."
        return await _http_exception_handler(
            request,
            HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail_payload),
        )

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
