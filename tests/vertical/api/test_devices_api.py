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
async def test_devices_api_list_location_and_status(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        devices = await client.get("/v1/devices", headers=headers)
        assert devices.status_code == 200
        payload = devices.json()["data"]
        assert [device["id"] for device in payload] == ["device-iphone-1", "device-ipad-1"]

        location = await client.get("/v1/devices/device-iphone-1/location", headers=headers)
        assert location.status_code == 200
        assert location.json()["data"]["latitude"] == pytest.approx(40.4168)
        assert location.json()["data"]["longitude"] == pytest.approx(-3.7038)

        status = await client.get("/v1/devices/device-iphone-1/status", headers=headers)
        assert status.status_code == 200
        assert status.json()["data"]["batteryStatus"] == "Charging"


@pytest.mark.asyncio
async def test_devices_api_actions_and_not_found(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = await _auth_headers(client)

        play = await client.post(
            "/v1/devices/device-iphone-1/actions/play-sound",
            headers=headers,
            json={"subject": "Find My iPhone Alert"},
        )
        assert play.status_code == 200
        assert play.json()["data"]["detail"] == "Sound command sent"

        message = await client.post(
            "/v1/devices/device-iphone-1/actions/message",
            headers=headers,
            json={"subject": "A Message", "message": "Hello", "sounds": True},
        )
        assert message.status_code == 200
        assert message.json()["data"]["detail"] == "Message command sent"

        lost = await client.post(
            "/v1/devices/device-iphone-1/actions/lost-mode",
            headers=headers,
            json={"number": "+34600123456", "text": "Call me", "newpasscode": "1234"},
        )
        assert lost.status_code == 200
        assert lost.json()["data"]["detail"] == "Lost mode command sent"

        missing = await client.get("/v1/devices/missing/location", headers=headers)
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "not_found"
