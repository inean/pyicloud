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
async def test_cli_reminders_commands(app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    listed = await runner.invoke(main, ["--api-url", "http://testserver", "reminders", "list"])
    assert listed.exit_code == 0
    assert set(json.loads(listed.output).keys()) == {"Personal", "Work"}

    added = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "reminders",
            "add",
            "--title",
            "Prepare release notes",
            "--description",
            "For sprint 12",
            "--collection",
            "Work",
            "--due-date",
            "2026-03-07T10:30:00+00:00",
        ],
    )
    assert added.exit_code == 0
    assert json.loads(added.output)["detail"] == "Reminder created"

    updated = await runner.invoke(main, ["--api-url", "http://testserver", "reminders", "list"])
    assert updated.exit_code == 0
    work_titles = [item["title"] for item in json.loads(updated.output)["Work"]]
    assert work_titles == ["Send status update", "Prepare release notes"]
