from __future__ import annotations

import pytest
from asyncclick.testing import CliRunner
from httpx import ASGITransport, AsyncClient

from pyicloud.api import create_app
from pyicloud.cli.main import main as api_cli_main
from pyicloud.cmdline import main as legacy_cli_main
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service


@pytest.mark.smoke
@pytest.mark.asyncio
async def test_api_healthcheck(tmp_path):
    app = create_app(
        auth_service=build_fake_auth_api_service(tmp_path),
        core_services=build_deterministic_core_services(),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.smoke
@pytest.mark.asyncio
async def test_cli_help_commands():
    runner = CliRunner()

    api_help = await runner.invoke(api_cli_main, ["--help"])
    assert api_help.exit_code == 0
    assert "pyicloud API-driven CLI" in api_help.output

    legacy_help = await runner.invoke(legacy_cli_main, ["--help"])
    assert legacy_help.exit_code == 0
    assert "Deprecated legacy CLI shim" in legacy_help.output
