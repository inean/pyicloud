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
            return response.json()
        return response.content

    monkeypatch.setattr("pyicloud.cli.main._api_request", fake_api_request)


@pytest.mark.asyncio
async def test_cli_account_commands(app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    devices = await runner.invoke(main, ["--api-url", "http://testserver", "account", "devices"])
    assert devices.exit_code == 0
    assert [item["id"] for item in json.loads(devices.output)] == ["device-iphone-1", "device-ipad-1"]

    family = await runner.invoke(main, ["--api-url", "http://testserver", "account", "family"])
    assert family.exit_code == 0
    assert [item["fullName"] for item in json.loads(family.output)] == ["Inean User", "Family Member"]

    storage = await runner.invoke(main, ["--api-url", "http://testserver", "account", "storage"])
    assert storage.exit_code == 0
    storage_payload = json.loads(storage.output)
    assert storage_payload["usage"]["total_storage_in_bytes"] == 500000000000
