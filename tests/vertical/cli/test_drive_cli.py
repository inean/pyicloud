from __future__ import annotations

import json
from pathlib import Path

import pytest
from asyncclick.testing import CliRunner
from httpx import ASGITransport, AsyncClient

from pyicloud.cli.main import main


def _patch_cli_api(monkeypatch: pytest.MonkeyPatch, app) -> None:
    async def fake_api_request(
        *,
        api_url: str,  # noqa: ARG001
        method: str,
        route: str,
        token: str | None = None,
        json_body=None,
        params=None,
        files=None,
    ):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            response = await client.request(
                method,
                route,
                headers=headers,
                json=json_body,
                params=params,
                files=files,
            )
        if response.status_code >= 400:
            raise RuntimeError(response.text)
        if response.headers.get("content-type", "").startswith("application/json"):
            payload = response.json()
            if isinstance(payload, dict) and "data" in payload:
                return payload["data"]
            return payload
        return response.content

    monkeypatch.setattr("pyicloud.cli.main._api_request", fake_api_request)


@pytest.mark.asyncio
async def test_cli_drive_commands(app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    token_file = tmp_path / "token.json"
    monkeypatch.setenv("PYICLOUD_API_TOKEN_FILE", str(token_file))
    _patch_cli_api(monkeypatch, app)
    runner = CliRunner()

    login = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "auth",
            "login",
            "--username",
            "success@example.com",
            "--password",
            "secret",
        ],
    )
    assert login.exit_code == 0
    assert token_file.exists()

    tree = await runner.invoke(main, ["--api-url", "http://testserver", "drive", "tree", "--path", "/"])
    assert tree.exit_code == 0
    assert [child["name"] for child in json.loads(tree.output)["children"]] == ["Documents", "Photos"]

    file_info = await runner.invoke(
        main,
        ["--api-url", "http://testserver", "drive", "file", "--path", "/Documents/notes.txt"],
    )
    assert file_info.exit_code == 0
    assert json.loads(file_info.output)["name"] == "notes.txt"

    download_target = tmp_path / "downloads" / "notes.txt"
    downloaded = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "drive",
            "file",
            "--path",
            "/Documents/notes.txt",
            "--download-to",
            str(download_target),
        ],
    )
    assert downloaded.exit_code == 0
    assert download_target.read_bytes() == b"hello from notes"

    mkdir = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "drive",
            "mkdir",
            "--parent-path",
            "/Documents",
            "--name",
            "Archive",
        ],
    )
    assert mkdir.exit_code == 0
    assert json.loads(mkdir.output)["detail"] == "Folder created"

    upload_source = tmp_path / "upload.txt"
    upload_source.write_text("Quarterly summary", encoding="utf-8")
    upload = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "drive",
            "upload",
            "--parent-path",
            "/Documents/Archive",
            "--file",
            str(upload_source),
        ],
    )
    assert upload.exit_code == 0
    assert json.loads(upload.output)["detail"] == "File uploaded"

    rename = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "drive",
            "rename",
            "--path",
            "/Documents/Archive/upload.txt",
            "--new-name",
            "report-2026.txt",
        ],
    )
    assert rename.exit_code == 0
    assert json.loads(rename.output)["detail"] == "Node renamed"

    delete = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "drive",
            "delete",
            "--path",
            "/Documents/Archive/report-2026.txt",
        ],
    )
    assert delete.exit_code == 0
    assert json.loads(delete.output)["detail"] == "Node deleted"
