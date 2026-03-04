from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pyicloud.adapters.services import legacy_core


def test_legacy_core_services_adapter_restores_endpoint_from_store(monkeypatch: pytest.MonkeyPatch):
    payload = {"webservices": {"findme": {"url": "https://example.test"}}}
    endpoint = object()
    calls: list[tuple[str, str, dict[str, Any]]] = []

    store = SimpleNamespace(load=lambda account_id: payload)

    class FakeEndpointFactory:
        def from_payload(self, *, username: str, password: str, payload: dict[str, Any]) -> object:
            calls.append((username, password, payload))
            return endpoint

    class FakePyiCloudServices:
        def __init__(self, endpoint: object):
            self.endpoint = endpoint

    monkeypatch.setattr(legacy_core, "PyiCloudServices", FakePyiCloudServices)
    adapter = legacy_core.LegacyCoreServicesAdapter(
        session_store=store,
        endpoint_factory=FakeEndpointFactory(),
    )

    services = adapter._services(username="user@example.com")

    assert isinstance(services, FakePyiCloudServices)
    assert services.endpoint is endpoint
    assert calls == [("user@example.com", "", payload)]


def test_legacy_core_services_adapter_raises_when_payload_missing():
    store = SimpleNamespace(load=lambda account_id: None)
    adapter = legacy_core.LegacyCoreServicesAdapter(
        session_store=store,
        endpoint_factory=SimpleNamespace(),
    )

    with pytest.raises(RuntimeError, match="No stored endpoint payload found for account"):
        adapter._services(username="user@example.com")
