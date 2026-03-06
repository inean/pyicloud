from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from pyicloud.adapters.access import InMemoryAccessControlStore
from pyicloud.api import create_app
from pyicloud.application.access_control import AccessControlApiService
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service


@pytest.fixture()
def app(tmp_path: Path):
    access_store = InMemoryAccessControlStore()
    access_control_service = AccessControlApiService(query=access_store, command=access_store)
    access_control_service.ensure_bootstrap_admin(strict_mode=True, bootstrap_username="admin@example.com")
    access_store.upsert_entry(
        username="member@example.com",
        roles=("member",),
        status="active",
        actor="admin@example.com",
    )
    auth_service = build_fake_auth_api_service(
        tmp_path,
        access_query=access_store,
        enforce_allowlist=True,
    )
    core_services = build_deterministic_core_services()
    return create_app(
        auth_service=auth_service,
        access_control_service=access_control_service,
        core_services=core_services,
    )


async def _login_token(client: AsyncClient, username: str) -> str:
    response = await client.post(
        "/v1/auth/challenge",
        json={"username": username, "password_envelope": "secret"},
    )
    assert response.status_code == 200
    return str(response.json()["data"]["access_token"])


@pytest.mark.asyncio
async def test_non_allowlisted_login_is_rejected_with_403(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(
            "/v1/auth/challenge",
            json={"username": "outside@example.com", "password_envelope": "secret"},
        )

    assert response.status_code == 403
    payload = response.json()["error"]
    assert payload["code"] == "forbidden"


@pytest.mark.asyncio
async def test_admin_can_manage_allowlist_and_member_cannot(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        admin_token = await _login_token(client, "admin@example.com")
        member_token = await _login_token(client, "member@example.com")

        denied = await client.get(
            "/v1/admin/allowlist",
            headers={"Authorization": f"Bearer {member_token}"},
        )
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "forbidden"

        listed = await client.get(
            "/v1/admin/allowlist",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert listed.status_code == 200
        usernames = [entry["username"] for entry in listed.json()["data"]["entries"]]
        assert usernames == ["admin@example.com", "member@example.com"]

        added = await client.post(
            "/v1/admin/allowlist",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"username": "new.user@example.com", "role": "member", "status": "active"},
        )
        assert added.status_code == 200
        assert added.json()["data"]["username"] == "new.user@example.com"

        promoted = await client.post(
            "/v1/admin/allowlist/new.user@example.com/role",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": "admin"},
        )
        assert promoted.status_code == 200
        assert promoted.json()["data"]["roles"] == ["admin"]

        removed = await client.delete(
            "/v1/admin/allowlist/new.user@example.com",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert removed.status_code == 200


@pytest.mark.asyncio
async def test_admin_api_guards_last_admin_removal(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        admin_token = await _login_token(client, "admin@example.com")

        remove_last_admin = await client.delete(
            "/v1/admin/allowlist/admin@example.com",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert remove_last_admin.status_code == 409
        assert remove_last_admin.json()["error"]["status"] == 409

        demote_last_admin = await client.post(
            "/v1/admin/allowlist/admin@example.com/role",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": "member"},
        )
        assert demote_last_admin.status_code == 409
