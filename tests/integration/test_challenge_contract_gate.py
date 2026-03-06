from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from pyicloud.api import create_app
from pyicloud.exceptions import PyiCloudAPIResponseError
from tests.fakes.auth_scenarios import build_deterministic_core_services, build_fake_auth_api_service

PROTECTED_DOMAIN_CASES = [
    ("list_devices", "GET", "/v1/devices", None, None),
    ("account_storage", "GET", "/v1/account/storage", None, None),
    ("drive_tree", "GET", "/v1/drive/tree", None, None),
    ("calendar_calendars", "GET", "/v1/calendar/calendars", None, None),
    ("contacts_all", "GET", "/v1/contacts", None, None),
    ("reminders_lists", "GET", "/v1/reminders", None, None),
    ("photos_albums", "GET", "/v1/photos/albums", None, None),
    ("ubiquity_tree", "GET", "/v1/ubiquity/tree", None, None),
]


async def _login_token(client: AsyncClient) -> str:
    response = await client.post(
        "/v1/auth/login",
        json={"username": "success@example.com", "password": "secret"},
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
    params: dict[str, object] | None,
    json_payload: dict[str, object] | None,
) -> None:
    auth_service = build_fake_auth_api_service(tmp_path)
    core_services = build_deterministic_core_services()
    setattr(core_services, service_method_name, _raise_upstream_expired)
    app = create_app(auth_service=auth_service, core_services=core_services)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        token = await _login_token(client)
        response = await client.request(
            http_method,
            path,
            headers={"Authorization": f"Bearer {token}"},
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
    }
    assert details["challenge_type"] == "session_refresh"
    assert details["account_id"] == "success@example.com"
    assert details["upstream_status"] == 450
    assert details["next_step"] == "auth.login"
    assert details["operation"] == f"{http_method} {path}"
