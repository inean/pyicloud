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
async def test_cli_observability_commands(app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    promql = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "observability",
            "promql",
            "--query",
            "up",
        ],
    )
    assert promql.exit_code == 0
    assert json.loads(promql.output)["language"] == "promql"

    pronql = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "observability",
            "pronql",
            "--query",
            "up",
        ],
    )
    assert pronql.exit_code != 0
    assert "No such command 'pronql'" in pronql.output

    logql_range = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "observability",
            "logql",
            "--query",
            '{service="api"}',
            "--start",
            "1710000000",
            "--end",
            "1710000600",
            "--step",
            "1m",
        ],
    )
    assert logql_range.exit_code == 0
    assert json.loads(logql_range.output)["data"]["resultType"] == "matrix"


@pytest.mark.asyncio
async def test_cli_observability_flow_table(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"access_token": "token-1"}), encoding="utf-8")
    monkeypatch.setenv("PYICLOUD_API_TOKEN_FILE", str(token_file))

    async def fake_api_request(**kwargs):  # noqa: ANN003
        return {
            "status": "success",
            "language": "logql",
            "data": {
                "resultType": "streams",
                "result": [
                    {
                        "stream": {"component": "pyicloud.upstream"},
                        "values": [
                            [
                                "1710000000000000000",
                                json.dumps(
                                    {
                                        "timestamp": 1710000000.0,
                                        "pyicloud.step": "signin",
                                        "method": "POST",
                                        "path": "/appleauth/auth/signin/init",
                                        "status_code": 200,
                                        "outcome": "success",
                                        "duration_ms": 20.0,
                                        "target_service": "apple.idmsa",
                                    }
                                ),
                            ]
                        ],
                    }
                ],
            },
            "warnings": [],
            "source": "loki",
        }

    monkeypatch.setattr("pyicloud.cli.main._api_request", fake_api_request)

    runner = CliRunner()
    result = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "observability",
            "flow",
            "--flow-id",
            "flow-1",
            "--format",
            "table",
        ],
    )
    assert result.exit_code == 0
    assert "timestamp" in result.output
    assert "signin" in result.output


@pytest.mark.asyncio
async def test_cli_observability_flow_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"access_token": "token-1"}), encoding="utf-8")
    monkeypatch.setenv("PYICLOUD_API_TOKEN_FILE", str(token_file))

    async def fake_api_request(**kwargs):  # noqa: ANN003
        return {
            "status": "success",
            "language": "logql",
            "events": [
                {
                    "timestamp": 1710000000.0,
                    "pyicloud.step": "find_devices",
                    "method": "POST",
                    "path": "/fmipservice/client/web/refreshClient",
                    "status_code": 200,
                    "outcome": "success",
                    "duration_ms": 33.0,
                    "target_service": "apple.findmy",
                }
            ],
            "source": "mock",
        }

    monkeypatch.setattr("pyicloud.cli.main._api_request", fake_api_request)

    runner = CliRunner()
    result = await runner.invoke(
        main,
        [
            "--api-url",
            "http://testserver",
            "observability",
            "flow",
            "--flow-id",
            "flow-2",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["flow_id"] == "flow-2"
    assert payload["events"][0]["pyicloud.step"] == "find_devices"
