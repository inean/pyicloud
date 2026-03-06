"""Application service for allowlist/admin management and authorization policy."""

from __future__ import annotations

from collections.abc import Iterable

from pyicloud.domain import AccessControlEntry, Conflict, Forbidden
from pyicloud.domain.api_models import AccessRole, AccessStatus, AuthPrincipal
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


class AccessControlApiService:
    """Coordinate allowlist checks, bootstrap admin setup, and admin mutations."""

    def __init__(
        self,
        *,
        query: AccessControlQueryPort,
        command: AccessControlCommandPort,
    ):
        self._query = query
        self._command = command

    @staticmethod
    def _assert_admin(actor: AuthPrincipal) -> None:
        if actor.role != "admin":
            raise Forbidden("Admin role is required")

    def ensure_bootstrap_admin(
        self,
        *,
        strict_mode: bool,
        bootstrap_username: str | None,
    ) -> AccessControlEntry | None:
        if not strict_mode:
            return None
        if self._query.active_admin_count() > 0:
            return None
        if not (bootstrap_username or "").strip():
            raise RuntimeError(
                "PYICLOUD_API_BOOTSTRAP_ADMIN must be configured when no active admin exists in non-dev runtime"
            )
        normalized_username = _normalize_username(bootstrap_username or "")
        return self._command.upsert_entry(
            username=normalized_username,
            roles=("admin",),
            status="active",
            actor="bootstrap",
        )

    def get_entry(self, *, username: str) -> AccessControlEntry | None:
        return self._query.get_entry(_normalize_username(username))

    def list_entries(self, *, actor: AuthPrincipal) -> tuple[AccessControlEntry, ...]:
        self._assert_admin(actor)
        return self._query.list_entries()

    def add_entry(
        self,
        *,
        actor: AuthPrincipal,
        username: str,
        roles: tuple[str, ...] = ("member",),
        status: str = "active",
    ) -> AccessControlEntry:
        self._assert_admin(actor)
        return self._command.upsert_entry(
            username=_normalize_username(username),
            roles=_normalize_roles(roles),
            status=_normalize_status(status),
            actor=actor.username,
        )

    def remove_entry(self, *, actor: AuthPrincipal, username: str) -> bool:
        self._assert_admin(actor)
        normalized_username = _normalize_username(username)
        existing = self._query.get_entry(normalized_username)
        if existing is None:
            return False
        if existing.status == "active" and "admin" in existing.roles and self._query.active_admin_count() <= 1:
            raise Conflict("Cannot remove the last active admin")
        return self._command.delete_entry(username=normalized_username, actor=actor.username)

    def set_role(self, *, actor: AuthPrincipal, username: str, role: str) -> AccessControlEntry | None:
        self._assert_admin(actor)
        normalized_username = _normalize_username(username)
        existing = self._query.get_entry(normalized_username)
        if existing is None:
            return None
        normalized_roles = _normalize_roles((role,))
        if existing.status == "active" and "admin" in existing.roles and "admin" not in normalized_roles:
            if self._query.active_admin_count() <= 1:
                raise Conflict("Cannot demote the last active admin")
        return self._command.upsert_entry(
            username=normalized_username,
            roles=normalized_roles,
            status=existing.status,
            actor=actor.username,
        )
