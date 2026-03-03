from __future__ import annotations

from types import SimpleNamespace

import pytest

from pyicloud.constants import Endpoints
from pyicloud.models.settings import Settings
from pyicloud.services import endpoint_adapter
from pyicloud.services.endpoint_adapter import LegacyServiceEndpointAdapter, build_endpoint_from_payload


def build_settings() -> Settings:
    return Settings.create(username="user@example.com", password="secret")


def test_endpoint_adapter_contains_and_getitem():
    settings = build_settings()
    api = {"webservices": {"findme": {"url": "https://findme.test"}}}
    adapter = LegacyServiceEndpointAdapter(api, settings=settings, session=SimpleNamespace())

    assert "findme" in adapter
    assert adapter["findme"] == "https://findme.test"


def test_endpoint_adapter_injects_client_id_param():
    settings = build_settings()
    api = {"webservices": {"findme": {"url": "https://findme.test"}}}
    adapter = LegacyServiceEndpointAdapter(api, settings=settings, session=SimpleNamespace())

    assert adapter.params["clientId"] == settings.client_settings.client_id


def test_endpoint_adapter_authenticate_raises_on_missing_service():
    settings = build_settings()
    api = {"webservices": {"findme": {"url": "https://findme.test"}}}
    adapter = LegacyServiceEndpointAdapter(api, settings=settings, session=SimpleNamespace())

    with pytest.raises(KeyError, match="Service not available"):
        adapter.authenticate("drivews")


def test_build_endpoint_from_payload_uses_legacy_session(monkeypatch):
    api = {"webservices": {"findme": {"url": "https://findme.test"}}}

    class FakeJar:
        def __init__(self):
            self.saved = []

        def set_cookie(self, cookie):
            self.saved.append(cookie)

    class FakeCookies:
        def __init__(self):
            self.jar = FakeJar()

    class FakeSession:
        def __init__(self, *, settings, auth_callback=None, error_callback=None):
            self.settings = settings
            self.auth_callback = auth_callback
            self.error_callback = error_callback
            self.headers = {}
            self.cookies = FakeCookies()

    cookie_load_calls = []

    def fake_settings_load(self):
        return None

    def fake_cookies_load(self, username: str):
        cookie_load_calls.append(username)
        return None

    monkeypatch.setattr(endpoint_adapter.SettingsFile, "loads", fake_settings_load)
    monkeypatch.setattr(endpoint_adapter.CookiesJar, "loads", fake_cookies_load)
    monkeypatch.setattr(endpoint_adapter, "LegacyServiceSessionAdapter", FakeSession)

    adapter = build_endpoint_from_payload(
        username="user@example.com",
        password="secret",
        payload=api,
    )

    assert isinstance(adapter, LegacyServiceEndpointAdapter)
    assert adapter["findme"] == "https://findme.test"
    assert adapter.session.headers["Origin"] == Endpoints.HOME
    assert adapter.session.headers["Referer"] == f"{Endpoints.HOME}/"
    assert cookie_load_calls == ["user@example.com"]
