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
async def test_cli_calendar_commands(app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    calendars = await runner.invoke(main, ["--api-url", "http://testserver", "calendar", "calendars"])
    assert calendars.exit_code == 0
    assert [item["title"] for item in json.loads(calendars.output)] == ["Work", "Personal"]

    events = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "calendar",
            "events",
            "--from-dt",
            "2026-03-06T00:00:00+01:00",
        ],
    )
    assert events.exit_code == 0
    assert [item["guid"] for item in json.loads(events.output)] == ["event-personal-1"]

    detail = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "calendar",
            "event-detail",
            "--calendar-guid",
            "cal-work-1",
            "--event-guid",
            "event-work-1",
        ],
    )
    assert detail.exit_code == 0
    assert json.loads(detail.output)["notes"] == "Discuss Q2 milestones"
