"""In-memory implementation for allowlist/admin access-control state."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from time import time

from pyicloud.domain.api_models import AccessControlEntry, AccessRole, AccessStatus
from pyicloud.ports import AccessControlCommandPort, AccessControlQueryPort

_VALID_ROLES: set[AccessRole] = {"member", "admin"}
_VALID_STATUS: set[AccessStatus] = {"active", "disabled"}


def _normalize_username(username: str) -> str:
    normalized = str(username).strip().lower()
    if not normalized:
        raise RuntimeError("Username cannot be empty")
    return normalized


def _normalize_roles(roles: Iterable[str]) -> tuple[AccessRole, ...]:
    normalized: list[AccessRole] = []
    for raw_role in roles:
        role = str(raw_role).strip().lower()
        if role not in _VALID_ROLES:
            raise RuntimeError(f"Unsupported role: {raw_role}")
        typed_role = role if role == "admin" else "member"
        if typed_role not in normalized:
            normalized.append(typed_role)
    if not normalized:
        raise RuntimeError("At least one role is required")
    return tuple(normalized)


def _normalize_status(status: str) -> AccessStatus:
    normalized = str(status).strip().lower()
    if normalized not in _VALID_STATUS:
        raise RuntimeError(f"Unsupported status: {status}")
    return normalized if normalized == "active" else "disabled"


class InMemoryAccessControlStore(AccessControlQueryPort, AccessControlCommandPort):
    """Store allowlist/admin records in process memory."""

    def __init__(self, *, clock: Callable[[], float] | None = None):
        self._clock = clock or time
        self._entries: dict[str, AccessControlEntry] = {}

    def get_entry(self, username: str) -> AccessControlEntry | None:
        normalized_username = _normalize_username(username)
        record = self._entries.get(normalized_username)
        if record is None:
            return None
        return record

    def list_entries(self) -> tuple[AccessControlEntry, ...]:
        ordered = sorted(self._entries.values(), key=lambda entry: entry.username)
        return tuple(ordered)

    def active_admin_count(self) -> int:
        return sum(1 for entry in self._entries.values() if entry.status == "active" and "admin" in entry.roles)

    def upsert_entry(
        self,
        *,
        username: str,
        roles: tuple[AccessRole, ...],
        status: AccessStatus,
        actor: str,
    ) -> AccessControlEntry:
        normalized_username = _normalize_username(username)
        normalized_roles = _normalize_roles(roles)
        normalized_status = _normalize_status(status)
        normalized_actor = _normalize_username(actor)

        existing = self._entries.get(normalized_username)
        now = int(self._clock())
        if existing is not None:
            if existing.roles == normalized_roles and existing.status == normalized_status:
                return existing
            next_entry = AccessControlEntry(
                username=normalized_username,
                roles=normalized_roles,
                status=normalized_status,
                acl_version=existing.acl_version + 1,
                created_by=existing.created_by,
                created_at=existing.created_at,
                updated_at=now,
            )
        else:
            next_entry = AccessControlEntry(
                username=normalized_username,
                roles=normalized_roles,
                status=normalized_status,
                acl_version=1,
                created_by=normalized_actor,
                created_at=now,
                updated_at=now,
            )
        self._entries[normalized_username] = next_entry
        return next_entry

    def delete_entry(self, *, username: str, actor: str) -> bool:
        _ = _normalize_username(actor)
        normalized_username = _normalize_username(username)
        return self._entries.pop(normalized_username, None) is not None
