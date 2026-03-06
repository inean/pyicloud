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
async def test_drive_api_tree_and_file_endpoints(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        tree = await client.get("/v1/drive/tree", headers=headers, params={"path": "/"})
        assert tree.status_code == 200
        assert [child["name"] for child in tree.json()["data"]["children"]] == ["Documents", "Photos"]

        metadata = await client.get("/v1/drive/file", headers=headers, params={"path": "/Documents/notes.txt"})
        assert metadata.status_code == 200
        assert metadata.json()["data"]["type"] == "file"

        download = await client.get(
            "/v1/drive/file",
            headers=headers,
            params={"path": "/Documents/notes.txt", "download": "true"},
        )
        assert download.status_code == 200
        assert download.content == b"hello from notes"
        assert "notes.txt" in download.headers["content-disposition"]


@pytest.mark.asyncio
async def test_drive_api_mutations(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        mkdir = await client.post(
            "/v1/drive/folders",
            headers=headers,
            json={"parent_path": "/Documents", "name": "Archive"},
        )
        assert mkdir.status_code == 200
        assert mkdir.json()["data"]["detail"] == "Folder created"

        upload = await client.post(
            "/v1/drive/upload",
            headers=headers,
            params={"parent_path": "/Documents/Archive"},
            files={"file": ("report.txt", b"Quarterly summary", "application/octet-stream")},
        )
        assert upload.status_code == 200
        assert upload.json()["data"]["detail"] == "File uploaded"

        rename = await client.patch(
            "/v1/drive/node",
            headers=headers,
            json={"path": "/Documents/Archive/report.txt", "new_name": "report-2026.txt"},
        )
        assert rename.status_code == 200
        assert rename.json()["data"]["detail"] == "Node renamed"

        renamed_download = await client.get(
            "/v1/drive/file",
            headers=headers,
            params={"path": "/Documents/Archive/report-2026.txt", "download": "true"},
        )
        assert renamed_download.status_code == 200
        assert renamed_download.content == b"Quarterly summary"

        delete = await client.delete(
            "/v1/drive/node",
            headers=headers,
            params={"path": "/Documents/Archive/report-2026.txt"},
        )
        assert delete.status_code == 200
        assert delete.json()["data"]["detail"] == "Node deleted"

        archive_tree = await client.get("/v1/drive/tree", headers=headers, params={"path": "/Documents/Archive"})
        assert archive_tree.status_code == 200
        assert archive_tree.json()["data"]["children"] == []
