from __future__ import annotations

import pytest

from pyicloud.adapters.access import InMemoryAccessControlStore
from pyicloud.application.access_control import AccessControlApiService
from pyicloud.domain import Conflict, Forbidden
from pyicloud.domain.api_models import AuthPrincipal


def _admin_principal() -> AuthPrincipal:
    return AuthPrincipal(
        username="admin@example.com",
        token_id="token-1",
        expires_at=9999999999,
        role="admin",
        acl_version=1,
    )


def _member_principal() -> AuthPrincipal:
    return AuthPrincipal(
        username="member@example.com",
        token_id="token-2",
        expires_at=9999999999,
        role="member",
        acl_version=1,
    )


def test_ensure_bootstrap_admin_requires_username_in_strict_mode() -> None:
    store = InMemoryAccessControlStore()
    service = AccessControlApiService(query=store, command=store)

    with pytest.raises(RuntimeError, match="PYICLOUD_API_BOOTSTRAP_ADMIN"):
        service.ensure_bootstrap_admin(strict_mode=True, bootstrap_username=None)


def test_ensure_bootstrap_admin_creates_first_admin_once() -> None:
    store = InMemoryAccessControlStore()
    service = AccessControlApiService(query=store, command=store)

    bootstrapped = service.ensure_bootstrap_admin(strict_mode=True, bootstrap_username="Root@Example.com")
    assert bootstrapped is not None
    assert bootstrapped.username == "root@example.com"
    assert "admin" in bootstrapped.roles
    assert service.ensure_bootstrap_admin(strict_mode=True, bootstrap_username="other@example.com") is None


def test_non_admin_cannot_manage_allowlist() -> None:
    store = InMemoryAccessControlStore()
    service = AccessControlApiService(query=store, command=store)

    with pytest.raises(Forbidden, match="Admin role"):
        service.list_entries(actor=_member_principal())


def test_last_admin_guard_blocks_remove_and_demote() -> None:
    store = InMemoryAccessControlStore()
    service = AccessControlApiService(query=store, command=store)
    service.ensure_bootstrap_admin(strict_mode=True, bootstrap_username="admin@example.com")

    with pytest.raises(Conflict, match="last active admin"):
        service.remove_entry(actor=_admin_principal(), username="admin@example.com")

    with pytest.raises(Conflict, match="last active admin"):
        service.set_role(actor=_admin_principal(), username="admin@example.com", role="member")
