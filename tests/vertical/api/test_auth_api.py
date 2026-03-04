from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_auth_login_success_and_session_lookup(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post(
            "/v1/auth/login",
            json={"username": "success@example.com", "password": "secret"},
        )
        assert login.status_code == 200
        payload = login.json()
        assert payload["status"] == "authenticated"
        token = payload["access_token"]

        session = await client.get("/v1/auth/session", headers={"Authorization": f"Bearer {token}"})
        assert session.status_code == 200
        assert session.json()["username"] == "success@example.com"


@pytest.mark.asyncio
async def test_auth_login_requires_security_code_then_authenticates(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post(
            "/v1/auth/login",
            json={"username": "requires2fa@example.com", "password": "secret"},
        )
        assert login.status_code == 200
        payload = login.json()
        assert payload["status"] == "challenge_required"
        challenge_id = payload["challenge_id"]

        wrong = await client.post(
            "/v1/auth/security-code",
            json={"challenge_id": challenge_id, "code": "000000"},
        )
        assert wrong.status_code == 401

        ok = await client.post(
            "/v1/auth/security-code",
            json={"challenge_id": challenge_id, "code": "123456"},
        )
        assert ok.status_code == 200
        assert ok.json()["status"] == "authenticated"


@pytest.mark.asyncio
async def test_auth_login_invalid_credentials(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/v1/auth/login",
            json={"username": "invalid@example.com", "password": "secret"},
        )
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_auth_logout_revokes_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post(
            "/v1/auth/login",
            json={"username": "success@example.com", "password": "secret"},
        )
        token = login.json()["access_token"]

        logout = await client.post("/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert logout.status_code == 200

        session = await client.get("/v1/auth/session", headers={"Authorization": f"Bearer {token}"})
        assert session.status_code == 401
