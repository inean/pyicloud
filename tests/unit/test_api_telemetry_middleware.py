from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from pyicloud.api import create_app
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service


async def _auth_headers(client: AsyncClient) -> dict[str, str]:
    login = await client.post(
        "/v1/auth/login",
        json={"username": "success@example.com", "password": "password"},
    )
    assert login.status_code == 200
    token = login.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_api_telemetry_logs_route_template(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog) -> None:
    monkeypatch.setenv("PYICLOUD_TELEMETRY_ENABLED", "true")
    monkeypatch.setenv("PYICLOUD_TELEMETRY_SAMPLE_RATE", "1.0")
    caplog.set_level(logging.INFO, logger="pyicloud.telemetry")

    app = create_app(
        auth_service=build_fake_auth_api_service(tmp_path),
        core_services=build_deterministic_core_services(),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)
        caplog.clear()
        response = await client.get("/v1/devices/device-iphone-1/status", headers=headers)
        assert response.status_code == 200

    assert caplog.records
    payload = json.loads(caplog.records[-1].message)
    assert payload["message"] == "api.request"
    assert payload["component"] == "api.route"
    assert payload["route"] == "/v1/devices/{device_id}/status"
    assert payload["method"] == "GET"
    assert payload["status"] == 200
    assert payload["duration_ms"] >= 0.0


@pytest.mark.asyncio
async def test_api_telemetry_can_be_disabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog) -> None:
    monkeypatch.setenv("PYICLOUD_TELEMETRY_ENABLED", "false")
    caplog.set_level(logging.INFO, logger="pyicloud.telemetry")

    app = create_app(
        auth_service=build_fake_auth_api_service(tmp_path),
        core_services=build_deterministic_core_services(),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)
        caplog.clear()
        response = await client.get("/v1/devices", headers=headers)
        assert response.status_code == 200

    assert caplog.records == []
