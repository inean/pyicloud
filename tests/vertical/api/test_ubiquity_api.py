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
async def test_ubiquity_api_tree_file_and_download(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        tree = await client.get("/v1/ubiquity/tree", headers=headers, params={"path": "/"})
        assert tree.status_code == 200
        assert [child["name"] for child in tree.json()["data"]["children"]] == ["Documents", "Notes"]

        metadata = await client.get(
            "/v1/ubiquity/file",
            headers=headers,
            params={"path": "/Documents/shared.txt"},
        )
        assert metadata.status_code == 200
        assert metadata.json()["data"]["type"] == "file"
        assert metadata.json()["data"]["name"] == "shared.txt"

        download = await client.get(
            "/v1/ubiquity/file",
            headers=headers,
            params={"path": "/Documents/shared.txt", "download": "true"},
        )
        assert download.status_code == 200
        assert download.content == b"shared-content"
        assert "shared.txt" in download.headers["content-disposition"]

        missing = await client.get("/v1/ubiquity/tree", headers=headers, params={"path": "/missing"})
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "not_found"
