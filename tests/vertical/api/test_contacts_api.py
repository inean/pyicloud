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
async def test_contacts_api_list(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        contacts = await client.get("/v1/contacts", headers=headers)
        assert contacts.status_code == 200
        payload = contacts.json()["data"]
        assert [item["displayName"] for item in payload] == ["Inean User", "Family Member"]
