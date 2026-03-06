from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from pyicloud.api import create_app
from pyicloud.exceptions import PyiCloudAPIResponseError
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service


@pytest.mark.asyncio
async def test_devices_list_maps_session_expired_to_auth_challenge(tmp_path):
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()

    def _raise_upstream_error(*, username: str):  # noqa: ARG001
        raise PyiCloudAPIResponseError("Client Error (450)", 450)

    core_services.list_devices = _raise_upstream_error  # type: ignore[method-assign]
    app = create_app(auth_service=auth_service, core_services=core_services)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post(
            "/v1/auth/challenge",
            json={"username": "success@example.com", "password_envelope": "secret"},
        )
        assert login.status_code == 200
        token = login.json()["data"]["access_token"]

        response = await client.get("/v1/devices", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    payload = response.json()["error"]
    assert payload["code"] == "auth_challenge_required"
    assert payload["details"]["upstream_status"] == 450
    assert payload["details"]["challenge_type"] == "session_refresh"
    assert payload["details"]["account_id"] == "success@example.com"
    assert payload["details"]["next_step"] == "auth.login"


@pytest.mark.asyncio
async def test_mutating_operation_requires_idempotency_key_on_auth_challenge(tmp_path):
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()

    async def _raise_upstream_error(*, username: str, device_id: str, subject: str):  # noqa: ARG001
        raise PyiCloudAPIResponseError("Client Error (450)", 450)

    core_services.device_play_sound = _raise_upstream_error  # type: ignore[method-assign]
    app = create_app(auth_service=auth_service, core_services=core_services)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post(
            "/v1/auth/challenge",
            json={"username": "success@example.com", "password_envelope": "secret"},
        )
        token = login.json()["data"]["access_token"]
        response = await client.post(
            "/v1/devices/device-iphone-1/actions/play-sound",
            headers={"Authorization": f"Bearer {token}"},
            json={"subject": "Ping"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "idempotency_key_required"


@pytest.mark.asyncio
async def test_operation_resume_marker_short_circuits_nested_auth_challenge(tmp_path):
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()

    def _raise_upstream_error(*, username: str):  # noqa: ARG001
        raise PyiCloudAPIResponseError("Client Error (450)", 450)

    core_services.list_devices = _raise_upstream_error  # type: ignore[method-assign]
    app = create_app(auth_service=auth_service, core_services=core_services)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post(
            "/v1/auth/challenge",
            json={"username": "success@example.com", "password_envelope": "secret"},
        )
        token = login.json()["data"]["access_token"]
        response = await client.get(
            "/v1/devices",
            headers={
                "Authorization": f"Bearer {token}",
                "X-PYICLOUD-Operation-Resume": "resume-1",
            },
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "operation_resume_failed"
