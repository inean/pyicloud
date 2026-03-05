from __future__ import annotations

import httpx
import pytest

from pyicloud.adapters.session.service_http import LegacyServiceSessionAdapter
from pyicloud.exceptions import PyiCloudAPIResponseError
from pyicloud.models.settings import Settings


def test_legacy_service_session_auth_headers_include_client_id():
    settings = Settings.create(username="user@example.com", password="secret")
    session = LegacyServiceSessionAdapter(settings=settings)
    try:
        headers = session._get_auth_headers()
        assert headers["X-Apple-OAuth-State"] == settings.client_settings.client_id
    finally:
        session.close()


def test_legacy_service_session_request_raises_on_non_json_error(monkeypatch):
    settings = Settings.create(username="user@example.com", password="secret")
    response = httpx.Response(
        500,
        headers={"content-type": "text/plain"},
        content=b"error",
        request=httpx.Request("GET", "https://example.test"),
    )

    def fake_request(self, method, url, **kwargs):  # noqa: ARG001
        return response

    monkeypatch.setattr(httpx.Client, "request", fake_request)

    session = LegacyServiceSessionAdapter(settings=settings)
    try:
        with pytest.raises(PyiCloudAPIResponseError):
            session.request("GET", "https://example.test")
    finally:
        session.close()
