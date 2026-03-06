from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient


async def _auth_headers(client: AsyncClient) -> dict[str, str]:
    login = await client.post(
        "/v1/auth/challenge",
        json={"username": "success@example.com", "password_envelope": "secret"},
    )
    assert login.status_code == 200
    payload = login.json()["data"]
    return {"Authorization": f"Bearer {payload['access_token']}"}


@pytest.mark.asyncio
async def test_account_api_devices_family_storage(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        devices = await client.get("/v1/account/devices", headers=headers)
        assert devices.status_code == 200
        assert [item["id"] for item in devices.json()["data"]] == ["device-iphone-1", "device-ipad-1"]

        family = await client.get("/v1/account/family", headers=headers)
        assert family.status_code == 200
        assert [item["fullName"] for item in family.json()["data"]] == ["Inean User", "Family Member"]

        storage = await client.get("/v1/account/storage", headers=headers)
        assert storage.status_code == 200
        payload = storage.json()["data"]
        assert payload["usage"]["total_storage_in_bytes"] == 500000000000
        assert payload["usages_by_media"]["photos"]["usage_in_bytes"] == 92000000000
