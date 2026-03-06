from __future__ import annotations

import json
from pathlib import Path

import pytest
from asyncclick.testing import CliRunner
from httpx import ASGITransport, AsyncClient

from pyicloud.api import create_app
from pyicloud.cli.main import main
from pyicloud.exceptions import PyiCloudAPIResponseError
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service


@pytest.mark.asyncio
async def test_cli_auth_login_session_logout_flow(app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    token_file = tmp_path / "token.json"
    monkeypatch.setenv("PYICLOUD_API_TOKEN_FILE", str(token_file))
    monkeypatch.setattr("pyicloud.cli.main._api_request", fake_api_request)

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
    assert json.loads(login.output)["status"] == "authenticated"

    session = await runner.invoke(main, ["--api-url", "http://testserver", "auth", "session"])
    assert session.exit_code == 0
    assert json.loads(session.output)["username"] == "success@example.com"

    logout = await runner.invoke(main, ["--api-url", "http://testserver", "auth", "logout"])
    assert logout.exit_code == 0
    assert not token_file.exists()


@pytest.mark.asyncio
async def test_cli_auth_security_code_flow_requires_password(app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    token_file = tmp_path / "token.json"
    monkeypatch.setenv("PYICLOUD_API_TOKEN_FILE", str(token_file))
    monkeypatch.setattr("pyicloud.cli.main._api_request", fake_api_request)

    runner = CliRunner()

    login = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "auth",
            "login",
            "--username",
            "requires2fa@example.com",
            "--password",
            "secret",
        ],
    )
    assert login.exit_code == 0
    challenge = json.loads(login.output)
    assert challenge["status"] == "challenge_required"

    complete = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "auth",
            "security-code",
            "--challenge-id",
            challenge["challenge_id"],
            "--code",
            "123456",
            "--password",
            "secret",
        ],
    )
    assert complete.exit_code == 0
    payload = json.loads(complete.output)
    assert payload["status"] == "authenticated"
    assert token_file.exists()


@pytest.mark.asyncio
async def test_cli_auto_recovers_from_auth_challenge_and_retries_read_operation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()
    base_list_devices = core_services.list_devices
    state = {"calls": 0}

    async def _challenge_then_list(*, username: str):
        state["calls"] += 1
        if state["calls"] == 1:
            raise PyiCloudAPIResponseError("Client Error (450)", 450)
        return await base_list_devices(username=username)

    core_services.list_devices = _challenge_then_list  # type: ignore[method-assign]
    app = create_app(auth_service=auth_service, core_services=core_services)

    async def fake_send_request(
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
            return await client.request(
                method,
                route,
                headers=headers,
                json=json_body,
                params=params,
                files=files,
            )

    def fake_prompt(text: str, **_kwargs):
        if text.startswith("Password for "):
            return "secret"
        if text == "Security code":
            return "123456"
        if text == "Apple ID":
            return "success@example.com"
        raise AssertionError(f"Unexpected prompt: {text}")

    monkeypatch.setattr("pyicloud.cli.main._send_request", fake_send_request)
    monkeypatch.setattr("pyicloud.cli.main.click.prompt", fake_prompt)
    monkeypatch.setattr("pyicloud.cli.main.click.confirm", lambda *_args, **_kwargs: True)

    token_file = tmp_path / "token.json"
    monkeypatch.setenv("PYICLOUD_API_TOKEN_FILE", str(token_file))
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

    devices = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "devices",
            "list",
        ],
    )
    assert devices.exit_code == 0
    payload = json.loads(devices.output)
    assert len(payload) == 2
    assert state["calls"] == 2
