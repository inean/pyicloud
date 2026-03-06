"""Schemas for admin allowlist management endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

AccessRole = Literal["member", "admin"]
AccessStatus = Literal["active", "disabled"]


class AllowlistEntryResponse(BaseModel):
    username: str
    roles: tuple[AccessRole, ...]
    status: AccessStatus
    acl_version: int
    created_by: str
    created_at: int
    updated_at: int


class AllowlistListResponse(BaseModel):
    entries: list[AllowlistEntryResponse]


class AllowlistUpsertRequest(BaseModel):
    username: str = Field(min_length=3)
    role: AccessRole = "member"
    status: AccessStatus = "active"


class AllowlistRoleRequest(BaseModel):
    role: AccessRole
