from __future__ import annotations

import json
from pathlib import Path

import pytest
from asyncclick.testing import CliRunner
from httpx import ASGITransport, AsyncClient

from pyicloud.cli.main import main


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
