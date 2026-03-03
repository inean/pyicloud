from __future__ import annotations

from types import SimpleNamespace

import pytest

from pyicloud.models.settings import Settings
from pyicloud.services.endpoint_adapter import LegacyServiceEndpointAdapter


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
