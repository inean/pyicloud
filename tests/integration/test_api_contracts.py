from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from pyicloud.api import create_app
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service


@pytest.fixture()
def app(tmp_path: Path):
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()
    return create_app(auth_service=auth_service, core_services=core_services)


async def _login_token(client: AsyncClient) -> str:
    response = await client.post(
        "/v1/auth/challenge",
        json={"username": "success@example.com", "password_envelope": "secret"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert set(payload.keys()) == {"data"}
    assert set(payload["data"].keys()) >= {"challenge_type", "access_token", "token_type", "expires_in"}
    return str(payload["data"]["access_token"])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_auth_and_domain_success_contract_envelopes(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        token = await _login_token(client)
        headers = {"Authorization": f"Bearer {token}"}

        session = await client.get("/v1/auth/session", headers=headers)
        assert session.status_code == 200
        payload = session.json()
        assert set(payload.keys()) == {"data"}
        assert set(payload["data"].keys()) == {"username", "token_id", "expires_at"}

        devices = await client.get("/v1/devices", headers=headers)
        assert devices.status_code == 200
        assert set(devices.json().keys()) == {"data"}
        assert isinstance(devices.json()["data"], list)

        storage = await client.get("/v1/account/storage", headers=headers)
        assert storage.status_code == 200
        assert set(storage.json().keys()) == {"data"}
        assert set(storage.json()["data"].keys()) == {"usage", "usages_by_media"}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_error_contract_envelope_shape(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        token = await _login_token(client)
        headers = {"Authorization": f"Bearer {token}"}

        missing = await client.get("/v1/devices/missing/location", headers=headers)
        assert missing.status_code == 404
        payload = missing.json()
        assert set(payload.keys()) == {"error"}
        assert set(payload["error"].keys()) == {"code", "message", "status", "details"}
        assert payload["error"]["code"] == "not_found"
        assert payload["error"]["status"] == 404

        invalid = await client.post(
            "/v1/observability/logql",
            headers=headers,
            json={"query": '{service="api"}', "start": 1},
        )
        assert invalid.status_code == 422
        invalid_payload = invalid.json()
        assert invalid_payload["error"]["code"] == "validation_error"
        assert invalid_payload["error"]["status"] == 422


@pytest.mark.integration
@pytest.mark.asyncio
async def test_binary_metadata_contract_shapes(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        token = await _login_token(client)
        headers = {"Authorization": f"Bearer {token}"}

        drive_metadata = await client.get("/v1/drive/file", headers=headers, params={"path": "/Documents/notes.txt"})
        assert drive_metadata.status_code == 200
        drive_payload = drive_metadata.json()["data"]
        assert set(drive_payload.keys()) >= {"path", "name", "type", "size"}

        photo_metadata = await client.get(
            "/v1/photos/asset",
            headers=headers,
            params={"asset_id": "photo-1", "album": "All Photos"},
        )
        assert photo_metadata.status_code == 200
        photo_payload = photo_metadata.json()["data"]
        assert set(photo_payload.keys()) >= {"id", "album", "filename", "versions"}

        ubiquity_metadata = await client.get(
            "/v1/ubiquity/file",
            headers=headers,
            params={"path": "/Documents/shared.txt"},
        )
        assert ubiquity_metadata.status_code == 200
        ubiquity_payload = ubiquity_metadata.json()["data"]
        assert set(ubiquity_payload.keys()) >= {"path", "name", "type", "item_id"}
