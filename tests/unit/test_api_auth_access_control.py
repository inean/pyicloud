from __future__ import annotations

import pytest

from pyicloud.adapters.access import InMemoryAccessControlStore
from pyicloud.adapters.session import InMemoryApiSessionStore
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.contexts.crosscutting.auth.application.api_auth import AuthApiService
from pyicloud.domain import Forbidden, Unauthorized


class _SuccessAuthService:
    async def run(self, *, account_id: str, request):  # noqa: ANN001, ARG002
        return None


def _build_service(
    *,
    access_store: InMemoryAccessControlStore | None,
    enforce_allowlist: bool,
    login_factory=None,
) -> AuthApiService:
    session_store = InMemoryApiSessionStore()
    signer = JwtTokenSigner(secret="test-secret-at-least-thirty-two-bytes")
    factory = login_factory or (lambda username, password: _SuccessAuthService())  # noqa: ARG005
    return AuthApiService(
        token_signer=signer,
        session_query=session_store,
        session_command=session_store,
        auth_service_factory=factory,
        access_query=access_store,
        enforce_allowlist=enforce_allowlist,
    )


@pytest.mark.asyncio
async def test_login_rejects_non_allowlisted_user_before_auth_flow() -> None:
    calls: list[tuple[str, str]] = []
    access_store = InMemoryAccessControlStore()

    service = _build_service(
        access_store=access_store,
        enforce_allowlist=True,
        login_factory=lambda username, password: calls.append((username, password)) or _SuccessAuthService(),
    )

    with pytest.raises(Forbidden, match="allowlisted"):
        await service.login(username="missing@example.com", password="secret")
    assert calls == []


@pytest.mark.asyncio
async def test_login_issues_token_with_role_and_acl_version_claims() -> None:
    access_store = InMemoryAccessControlStore()
    access_store.upsert_entry(
        username="admin@example.com",
        roles=("admin",),
        status="active",
        actor="bootstrap",
    )
    service = _build_service(access_store=access_store, enforce_allowlist=True)

    payload = await service.login(username="admin@example.com", password="secret")
    principal = service.session(token=str(payload["access_token"]))

    assert principal.role == "admin"
    assert principal.acl_version == 1


@pytest.mark.asyncio
async def test_session_rejects_stale_acl_version_after_allowlist_change() -> None:
    access_store = InMemoryAccessControlStore()
    access_store.upsert_entry(
        username="user@example.com",
        roles=("member",),
        status="active",
        actor="bootstrap",
    )
    service = _build_service(access_store=access_store, enforce_allowlist=True)

    payload = await service.login(username="user@example.com", password="secret")
    token = str(payload["access_token"])

    access_store.upsert_entry(
        username="user@example.com",
        roles=("admin",),
        status="active",
        actor="admin@example.com",
    )

    with pytest.raises(Unauthorized, match="stale"):
        service.session(token=token)


@pytest.mark.asyncio
async def test_relaxed_mode_allows_unlisted_user_with_default_acl_claims() -> None:
    service = _build_service(access_store=InMemoryAccessControlStore(), enforce_allowlist=False)

    payload = await service.login(username="unlisted@example.com", password="secret")
    principal = service.session(token=str(payload["access_token"]))

    assert principal.role == "member"
    assert principal.acl_version == 0
