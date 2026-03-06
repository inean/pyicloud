from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from pyicloud.api import create_app
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service


@pytest.fixture()
def app(tmp_path: Path):
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()
    return create_app(auth_service=auth_service, core_services=core_services)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_successful_auth_and_core_service_flow(app, tmp_path: Path):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post(
            "/v1/auth/challenge",
            json={"username": "success@example.com", "password_envelope": "secret"},
        )
        assert login.status_code == 200
        payload = login.json()["data"]
        assert payload["challenge_type"] == "authenticated"
        token = payload["access_token"]

        session_file = tmp_path / "sessions" / "successexamplecom.json"
        assert session_file.exists()
        stored_payload = json.loads(session_file.read_text(encoding="utf-8"))
        assert stored_payload["webservices"]["findme"]["url"] == "https://findme.example.test"

        headers = {"Authorization": f"Bearer {token}"}

        session = await client.get("/v1/auth/session", headers=headers)
        assert session.status_code == 200
        assert session.json()["data"]["username"] == "success@example.com"

        devices = await client.get("/v1/devices", headers=headers)
        assert devices.status_code == 200
        assert len(devices.json()["data"]) == 2

        account = await client.get("/v1/account/storage", headers=headers)
        assert account.status_code == 200
        assert account.json()["data"]["usage"]["total_storage_in_bytes"] == 500000000000

        drive = await client.get("/v1/drive/tree", params={"path": "/"}, headers=headers)
        assert drive.status_code == 200
        assert [child["name"] for child in drive.json()["data"]["children"]] == ["Documents", "Photos"]

        calendar = await client.get("/v1/calendar/calendars", headers=headers)
        assert calendar.status_code == 200
        assert [item["title"] for item in calendar.json()["data"]] == ["Work", "Personal"]

        contacts = await client.get("/v1/contacts", headers=headers)
        assert contacts.status_code == 200
        assert [item["displayName"] for item in contacts.json()["data"]] == ["Inean User", "Family Member"]

        reminders = await client.get("/v1/reminders", headers=headers)
        assert reminders.status_code == 200
        assert set(reminders.json()["data"].keys()) == {"Personal", "Work"}

        photos = await client.get("/v1/photos/albums", headers=headers)
        assert photos.status_code == 200
        assert [item["name"] for item in photos.json()["data"]] == ["All Photos", "Favorites"]

        ubiquity = await client.get("/v1/ubiquity/tree", params={"path": "/"}, headers=headers)
        assert ubiquity.status_code == 200
        assert [item["name"] for item in ubiquity.json()["data"]["children"]] == ["Documents", "Notes"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_security_code_challenge_flow(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        challenge = await client.post(
            "/v1/auth/challenge",
            json={"username": "requires2fa@example.com", "password_envelope": "secret"},
        )
        assert challenge.status_code == 200
        challenge_payload = challenge.json()["data"]
        assert challenge_payload["challenge_type"] == "security_code_required"

        invalid = await client.post(
            "/v1/auth/challenge",
            json={
                "challenge_id": challenge_payload["challenge_id"],
                "security_code": "000000",
                "password_envelope": "secret",
                "session_id": challenge_payload["session_id"],
            },
        )
        assert invalid.status_code == 401

        valid = await client.post(
            "/v1/auth/challenge",
            json={
                "challenge_id": challenge_payload["challenge_id"],
                "security_code": "123456",
                "password_envelope": "secret",
                "session_id": challenge_payload["session_id"],
            },
        )
        assert valid.status_code == 200
        token = valid.json()["data"]["access_token"]

        devices = await client.get("/v1/devices", headers={"Authorization": f"Bearer {token}"})
        assert devices.status_code == 200
