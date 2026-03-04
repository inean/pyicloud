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
async def test_cli_devices_commands(app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    listed = await runner.invoke(main, ["--api-url", "http://testserver", "devices", "list"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.output)
    assert [device["id"] for device in listed_payload] == ["device-iphone-1", "device-ipad-1"]

    location = await runner.invoke(main, ["--api-url", "http://testserver", "devices", "location", "device-iphone-1"])
    assert location.exit_code == 0
    assert json.loads(location.output)["latitude"] == pytest.approx(40.4168)

    status = await runner.invoke(main, ["--api-url", "http://testserver", "devices", "status", "device-iphone-1"])
    assert status.exit_code == 0
    assert json.loads(status.output)["batteryStatus"] == "Charging"

    play_sound = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "devices",
            "play-sound",
            "device-iphone-1",
        ],
    )
    assert play_sound.exit_code == 0
    assert json.loads(play_sound.output)["detail"] == "Sound command sent"

    message = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "devices",
            "message",
            "device-iphone-1",
            "--message",
            "Hello",
            "--sounds",
        ],
    )
    assert message.exit_code == 0
    assert json.loads(message.output)["detail"] == "Message command sent"

    lost_mode = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "devices",
            "lost-mode",
            "device-iphone-1",
            "--number",
            "+34600123456",
            "--text",
            "Call me",
            "--newpasscode",
            "1234",
        ],
    )
    assert lost_mode.exit_code == 0
    assert json.loads(lost_mode.output)["detail"] == "Lost mode command sent"
