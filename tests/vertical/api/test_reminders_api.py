from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient


async def _auth_headers(client: AsyncClient) -> dict[str, str]:
    login = await client.post(
        "/v1/auth/challenge",
        json={"username": "success@example.com", "password_envelope": "secret"},
    )
    assert login.status_code == 200
    payload = login.json()["data"]
    return {"Authorization": f"Bearer {payload['access_token']}"}


@pytest.mark.asyncio
async def test_reminders_api_list_and_create(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        listed = await client.get("/v1/reminders", headers=headers)
        assert listed.status_code == 200
        payload = listed.json()["data"]
        assert set(payload.keys()) == {"Personal", "Work"}
        assert payload["Personal"][0]["title"] == "Buy milk"

        created = await client.post(
            "/v1/reminders",
            headers=headers,
            json={
                "title": "Prepare release notes",
                "description": "For sprint 12",
                "collection": "Work",
                "due_date": "2026-03-07T10:30:00+00:00",
            },
        )
        assert created.status_code == 200
        assert created.json()["data"]["detail"] == "Reminder created"

        updated = await client.get("/v1/reminders", headers=headers)
        assert updated.status_code == 200
        work_titles = [item["title"] for item in updated.json()["data"]["Work"]]
        assert work_titles == ["Send status update", "Prepare release notes"]
