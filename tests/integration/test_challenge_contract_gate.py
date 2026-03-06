from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from pyicloud.api import create_app
from pyicloud.exceptions import PyiCloudAPIResponseError
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service

QueryParamValue = str | int | float | bool | None
RequestParams = dict[str, QueryParamValue] | None

PROTECTED_DOMAIN_CASES = [
    ("list_devices", "GET", "/v1/devices", None, None),
    ("device_play_sound", "POST", "/v1/devices/device-iphone-1/actions/play-sound", None, {"subject": "Ping"}),
    ("account_storage", "GET", "/v1/account/storage", None, None),
    ("account_family", "GET", "/v1/account/family", None, None),
    ("drive_tree", "GET", "/v1/drive/tree", None, None),
    ("drive_file_metadata", "GET", "/v1/drive/file", {"path": "/Documents/notes.txt"}, None),
    ("calendar_calendars", "GET", "/v1/calendar/calendars", None, None),
    (
        "calendar_event_detail",
        "GET",
        "/v1/calendar/event-detail",
        {"calendar_guid": "cal-work-1", "event_guid": "event-work-1"},
        None,
    ),
    ("contacts_all", "GET", "/v1/contacts", None, None),
    ("reminders_lists", "GET", "/v1/reminders", None, None),
    ("reminders_create", "POST", "/v1/reminders", None, {"title": "challenge check"}),
    ("photos_albums", "GET", "/v1/photos/albums", None, None),
    ("photo_asset_metadata", "GET", "/v1/photos/asset", {"asset_id": "photo-1", "album": "All Photos"}, None),
    ("ubiquity_tree", "GET", "/v1/ubiquity/tree", None, None),
    ("ubiquity_file_metadata", "GET", "/v1/ubiquity/file", {"path": "/Documents/shared.txt"}, None),
]


async def _login_token(client: AsyncClient) -> str:
    response = await client.post(
        "/v1/auth/challenge",
        json={"username": "success@example.com", "password_envelope": "secret"},
    )
    assert response.status_code == 200
    return str(response.json()["data"]["access_token"])


async def _raise_upstream_expired(**_: object) -> object:
    raise PyiCloudAPIResponseError("Client Error (450)", 450)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("service_method_name", "http_method", "path", "params", "json_payload"),
    PROTECTED_DOMAIN_CASES,
)
async def test_challenge_contract_is_enforced_for_all_protected_domains(
    tmp_path: Path,
    service_method_name: str,
    http_method: str,
    path: str,
    params: RequestParams,
    json_payload: dict[str, object] | None,
) -> None:
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()
    setattr(core_services, service_method_name, _raise_upstream_expired)
    app = create_app(auth_service=auth_service, core_services=core_services)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        token = await _login_token(client)
        headers = {"Authorization": f"Bearer {token}"}
        if http_method in {"POST", "PUT", "PATCH", "DELETE"}:
            headers["Idempotency-Key"] = f"idem-{service_method_name}"
        response = await client.request(
            http_method,
            path,
            headers=headers,
            params=params,
            json=json_payload,
        )

    assert response.status_code == 401
    payload = response.json()["error"]
    assert payload["code"] == "auth_challenge_required"
    assert payload["status"] == 401
    details = payload["details"]
    assert set(details.keys()) >= {
        "challenge_id",
        "challenge_type",
        "account_id",
        "flow_id",
        "expires_at",
        "next_step",
        "retryable",
        "upstream_status",
        "operation",
        "operation_id",
    }
    assert details["challenge_type"] == "session_refresh"
    assert details["account_id"] == "success@example.com"
    assert details["upstream_status"] == 450
    assert details["next_step"] == "auth.login"
    assert details["operation"] == f"{http_method} {path}"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mutating_operation_requires_idempotency_key_for_suspension(tmp_path: Path) -> None:
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()
    setattr(core_services, "reminders_create", _raise_upstream_expired)
    app = create_app(auth_service=auth_service, core_services=core_services)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        token = await _login_token(client)
        response = await client.post(
            "/v1/reminders",
            headers={"Authorization": f"Bearer {token}"},
            json={"title": "missing key"},
        )

    assert response.status_code == 400
    payload = response.json()["error"]
    assert payload["code"] == "idempotency_key_required"
