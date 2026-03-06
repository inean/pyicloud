"""Authentication request/response schemas for API endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AuthLoginRequest(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=1)


class AuthSecurityCodeRequest(BaseModel):
    challenge_id: str = Field(min_length=1)
    code: str = Field(pattern=r"^\d{6}$")
    password: str = Field(min_length=1)
    username: str | None = Field(default=None, min_length=3)


class AuthLoginResponse(BaseModel):
    status: Literal["authenticated", "challenge_required"]
    access_token: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    challenge_id: str | None = None
    challenge_ttl: int | None = None
    flow_id: str | None = None
    challenge_type: str | None = None
    account_id: str | None = None
    expires_at: int | None = None
    next_step: str | None = None
    retryable: bool | None = None


class AuthSessionResponse(BaseModel):
    username: str
    token_id: str
    expires_at: int


class SimpleOkResponse(BaseModel):
    ok: bool = True
    detail: str
