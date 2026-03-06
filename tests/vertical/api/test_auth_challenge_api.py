from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from pyicloud.exceptions import PyiCloudAPIResponseError


@pytest.mark.asyncio
async def test_auth_challenge_password_and_authenticated_flow(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        start = await client.post("/v1/auth/challenge", json={"username": "success@example.com"})
        assert start.status_code == 200
        start_payload = start.json()["data"]
        assert start_payload["challenge_type"] == "password_required"

        complete = await client.post(
            "/v1/auth/challenge",
            json={
                "challenge_id": start_payload["challenge_id"],
                "password_envelope": "secret",
            },
        )
        assert complete.status_code == 200
        payload = complete.json()["data"]
        assert payload["challenge_type"] == "authenticated"
        assert payload["access_token"]


@pytest.mark.asyncio
async def test_auth_challenge_security_code_flow(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        start = await client.post(
            "/v1/auth/challenge",
            json={"username": "requires2fa@example.com", "password_envelope": "secret"},
        )
        assert start.status_code == 200
        first = start.json()["data"]
        assert first["challenge_type"] == "security_code_required"

        complete = await client.post(
            "/v1/auth/challenge",
            json={
                "challenge_id": first["challenge_id"],
                "password_envelope": "secret",
                "security_code": "123456",
            },
        )
        assert complete.status_code == 200
        assert complete.json()["data"]["challenge_type"] == "authenticated"


@pytest.mark.asyncio
async def test_auth_challenge_rejects_invalid_transition(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        start = await client.post("/v1/auth/challenge", json={"username": "success@example.com"})
        assert start.status_code == 200
        challenge_id = start.json()["data"]["challenge_id"]

        invalid = await client.post(
            "/v1/auth/challenge",
            json={"challenge_id": challenge_id, "security_code": "123456"},
        )
        assert invalid.status_code == 400
        assert invalid.json()["error"]["code"] == "http_error"


@pytest.mark.asyncio
async def test_auth_challenge_operation_resume_contract(app):
    challenge = app.state.auth_service.issue_operation_challenge(
        account_id="success@example.com",
        upstream_status=450,
        operation="GET /v1/devices",
        reason="session expired",
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        pending = await client.post(
            "/v1/auth/challenge",
            json={"challenge_id": challenge["challenge_id"]},
        )
        assert pending.status_code == 200
        payload = pending.json()["data"]
        assert payload["challenge_type"] == "operation_resume_required"
        assert payload["operation"] == "GET /v1/devices"


@pytest.mark.asyncio
async def test_auth_challenge_resumes_suspended_operation_server_side(app):
    calls = {"count": 0}
    original = app.state.core_services.list_devices

    async def _first_fails_then_succeeds(**kwargs):  # noqa: ANN003
        calls["count"] += 1
        if calls["count"] == 1:
            raise PyiCloudAPIResponseError("Client Error (450)", 450)
        return await original(**kwargs)

    app.state.core_services.list_devices = _first_fails_then_succeeds

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post(
            "/v1/auth/login",
            json={"username": "success@example.com", "password": "secret"},
        )
        token = login.json()["data"]["access_token"]

        challenge_required = await client.get(
            "/v1/devices",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert challenge_required.status_code == 401
        challenge_id = challenge_required.json()["error"]["details"]["challenge_id"]

        pending = await client.post("/v1/auth/challenge", json={"challenge_id": challenge_id})
        assert pending.status_code == 200
        assert pending.json()["data"]["challenge_type"] == "operation_resume_required"

        resumed = await client.post(
            "/v1/auth/challenge",
            json={"challenge_id": challenge_id, "password_envelope": "secret"},
        )
        assert resumed.status_code == 200
        payload = resumed.json()["data"]
        assert payload["challenge_type"] == "authenticated"
        assert payload["operation_status"] == 200
        assert isinstance(payload["operation_result"]["data"], list)
