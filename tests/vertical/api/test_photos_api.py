from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient


async def _auth_headers(client: AsyncClient) -> dict[str, str]:
    login = await client.post(
        "/v1/auth/login",
        json={"username": "success@example.com", "password": "secret"},
    )
    assert login.status_code == 200
    payload = login.json()["data"]
    return {"Authorization": f"Bearer {payload['access_token']}"}


@pytest.mark.asyncio
async def test_photos_api_albums_assets_metadata_and_download(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        albums = await client.get("/v1/photos/albums", headers=headers)
        assert albums.status_code == 200
        assert [item["name"] for item in albums.json()["data"]] == ["All Photos", "Favorites"]

        assets = await client.get(
            "/v1/photos/assets",
            headers=headers,
            params={"album": "All Photos", "limit": 1, "offset": 1},
        )
        assert assets.status_code == 200
        assert [item["id"] for item in assets.json()["data"]] == ["photo-2"]

        metadata = await client.get(
            "/v1/photos/asset",
            headers=headers,
            params={"asset_id": "photo-1", "album": "All Photos"},
        )
        assert metadata.status_code == 200
        assert metadata.json()["data"]["filename"] == "beach.jpg"

        download = await client.get(
            "/v1/photos/download",
            headers=headers,
            params={"asset_id": "photo-1", "album": "All Photos", "version": "original"},
        )
        assert download.status_code == 200
        assert download.content == b"photo-1-bytes"
        assert "beach.jpg" in download.headers["content-disposition"]

        missing = await client.get(
            "/v1/photos/asset",
            headers=headers,
            params={"asset_id": "missing", "album": "All Photos"},
        )
        assert missing.status_code == 404
