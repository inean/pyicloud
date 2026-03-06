"""Shared dependency providers for API routers."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request, status

from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.application.observability import ObservabilityApi
from pyicloud.domain import Unauthorized


def get_auth_service(request: Request) -> AuthApiService:
    """Resolve auth application service from app state."""
    return request.app.state.auth_service


def get_core_services(request: Request) -> CoreServicesApi:
    """Resolve core-services application facade from app state."""
    return request.app.state.core_services


def get_observability_service(request: Request) -> ObservabilityApi:
    """Resolve observability application facade from app state."""
    return request.app.state.observability_service


def extract_token(authorization: str | None = Header(default=None)) -> str:
    """Extract bearer token from the Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def get_username(
    token: str = Depends(extract_token),
    service: AuthApiService = Depends(get_auth_service),
) -> str:
    """Resolve authenticated username from API token."""
    try:
        principal = service.session(token=token)
    except Unauthorized as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    return principal.username
