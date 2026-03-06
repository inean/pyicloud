"""Admin allowlist management API routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path, status

from pyicloud.contexts.crosscutting.auth.application.access_control import AccessControlApiService
from pyicloud.domain import AccessControlEntry, AuthPrincipal, Conflict, Forbidden

from ..dependencies import get_access_control_service, require_admin_principal
from ..responses import ok
from ..schemas import (
    AllowlistEntryResponse,
    AllowlistListResponse,
    AllowlistRoleRequest,
    AllowlistUpsertRequest,
    DataEnvelope,
    SimpleOkResponse,
)

router = APIRouter()
LOGGER = logging.getLogger("pyicloud.audit")


def _to_allowlist_entry_response(entry: AccessControlEntry) -> AllowlistEntryResponse:
    return AllowlistEntryResponse(
        username=entry.username,
        roles=entry.roles,
        status=entry.status,
        acl_version=entry.acl_version,
        created_by=entry.created_by,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


@router.get("/v1/admin/allowlist", response_model=DataEnvelope)
def admin_allowlist_list(
    principal: AuthPrincipal = Depends(require_admin_principal),
    service: AccessControlApiService = Depends(get_access_control_service),
) -> DataEnvelope:
    entries = service.list_entries(actor=principal)
    LOGGER.info("audit_event type=allowlist_list actor=%s count=%s", principal.username, len(entries))
    payload = AllowlistListResponse(entries=[_to_allowlist_entry_response(entry) for entry in entries])
    return ok(payload)


@router.post("/v1/admin/allowlist", response_model=DataEnvelope)
def admin_allowlist_add(
    payload: AllowlistUpsertRequest,
    principal: AuthPrincipal = Depends(require_admin_principal),
    service: AccessControlApiService = Depends(get_access_control_service),
) -> DataEnvelope:
    try:
        entry = service.add_entry(
            actor=principal,
            username=payload.username,
            roles=(payload.role,),
            status=payload.status,
        )
    except Forbidden as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    LOGGER.info(
        "audit_event type=allowlist_add actor=%s target=%s role=%s status=%s",
        principal.username,
        entry.username,
        entry.role,
        entry.status,
    )
    return ok(_to_allowlist_entry_response(entry))


@router.delete("/v1/admin/allowlist/{username}", response_model=DataEnvelope)
def admin_allowlist_remove(
    username: str = Path(..., min_length=3),
    principal: AuthPrincipal = Depends(require_admin_principal),
    service: AccessControlApiService = Depends(get_access_control_service),
) -> DataEnvelope:
    try:
        removed = service.remove_entry(actor=principal, username=username)
    except Forbidden as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    except Conflict as err:
        LOGGER.info("audit_event type=allowlist_remove_denied actor=%s target=%s", principal.username, username)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err
    if not removed:
        LOGGER.info("audit_event type=allowlist_remove_missing actor=%s target=%s", principal.username, username)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Allowlist entry not found: {username}")
    LOGGER.info("audit_event type=allowlist_remove actor=%s target=%s", principal.username, username)
    return ok(SimpleOkResponse(detail="Allowlist entry removed"))


@router.post("/v1/admin/allowlist/{username}/role", response_model=DataEnvelope)
def admin_allowlist_set_role(
    payload: AllowlistRoleRequest,
    username: str = Path(..., min_length=3),
    principal: AuthPrincipal = Depends(require_admin_principal),
    service: AccessControlApiService = Depends(get_access_control_service),
) -> DataEnvelope:
    try:
        entry = service.set_role(actor=principal, username=username, role=payload.role)
    except Forbidden as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    except Conflict as err:
        LOGGER.info("audit_event type=allowlist_role_denied actor=%s target=%s", principal.username, username)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err
    if entry is None:
        LOGGER.info("audit_event type=allowlist_role_missing actor=%s target=%s", principal.username, username)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Allowlist entry not found: {username}")
    LOGGER.info(
        "audit_event type=allowlist_role actor=%s target=%s role=%s",
        principal.username,
        entry.username,
        entry.role,
    )
    return ok(_to_allowlist_entry_response(entry))
