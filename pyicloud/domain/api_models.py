"""Domain models used by API authentication services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

AccessRole = Literal["member", "admin"]
AccessStatus = Literal["active", "disabled"]
SuspendedOperationState = Literal["pending_auth", "resuming", "completed", "failed", "expired"]


@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    """Authenticated principal recovered from bearer token claims."""

    username: str
    token_id: str
    expires_at: int
    role: AccessRole = "member"
    acl_version: int = 0


@dataclass(frozen=True, slots=True)
class AccessControlEntry:
    """Allowlist/admin record used for API access-control decisions."""

    username: str
    roles: tuple[AccessRole, ...]
    status: AccessStatus
    acl_version: int
    created_by: str
    created_at: int
    updated_at: int

    @property
    def role(self) -> AccessRole:
        """Resolve the primary role used by token claims and authorization checks."""
        if "admin" in self.roles:
            return "admin"
        return "member"


@dataclass(frozen=True, slots=True)
class SuspendedOperation:
    """Persisted record for a backend operation paused pending auth challenge completion."""

    operation_id: str
    account_id: str
    method: str
    path: str
    query_string: str
    body_text: str | None
    content_type: str | None
    idempotency_key: str | None
    state: SuspendedOperationState
    challenge_id: str | None
    created_at: int
    updated_at: int
    expires_at: int
    response_status: int | None = None
    response_payload: dict[str, Any] | None = None
    error: str | None = None
