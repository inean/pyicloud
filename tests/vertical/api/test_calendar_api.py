from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient


async def _auth_headers(client: AsyncClient) -> dict[str, str]:
    login = await client.post(
        "/v1/auth/login",
        json={"username": "success@example.com", "password": "secret"},
    )
    assert login.status_code == 200
    payload = login.json()["data"]
    return {"Authorization": f"Bearer {payload['access_token']}"}


@pytest.mark.asyncio
async def test_calendar_api_calendars_events_and_detail(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        calendars = await client.get("/v1/calendar/calendars", headers=headers)
        assert calendars.status_code == 200
        assert [item["title"] for item in calendars.json()["data"]] == ["Work", "Personal"]

        events = await client.get("/v1/calendar/events", headers=headers)
        assert events.status_code == 200
        assert [item["guid"] for item in events.json()["data"]] == ["event-work-1", "event-personal-1"]

        filtered_events = await client.get(
            "/v1/calendar/events",
            headers=headers,
            params={"from_dt": "2026-03-06T00:00:00+01:00"},
        )
        assert filtered_events.status_code == 200
        assert [item["guid"] for item in filtered_events.json()["data"]] == ["event-personal-1"]

        detail = await client.get(
            "/v1/calendar/event-detail",
            headers=headers,
            params={"calendar_guid": "cal-work-1", "event_guid": "event-work-1"},
        )
        assert detail.status_code == 200
        assert detail.json()["data"]["notes"] == "Discuss Q2 milestones"

        missing = await client.get(
            "/v1/calendar/event-detail",
            headers=headers,
            params={"calendar_guid": "cal-work-1", "event_guid": "missing"},
        )
        assert missing.status_code == 404
