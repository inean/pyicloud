from __future__ import annotations

from pyicloud.application import ServiceEndpointRestoreService


class FakeStore:
    def __init__(self, payload):
        self._payload = payload
        self.calls = []

    def load(self, account_id: str):
        self.calls.append(account_id)
        return self._payload

    def save(self, account_id: str, payload):  # pragma: no cover - not used by this service
        raise AssertionError("save should not be called")

    def clear(self, account_id: str):  # pragma: no cover - not used by this service
        raise AssertionError("clear should not be called")


class FakeFactory:
    def __init__(self):
        self.calls = []

    def from_payload(self, *, username: str, password: str, payload):
        self.calls.append((username, password, payload))
        return {"endpoint": True}


def test_restore_returns_none_when_payload_missing():
    service = ServiceEndpointRestoreService(
        store=FakeStore(payload=None),  # type: ignore[arg-type]
        endpoint_factory=FakeFactory(),  # type: ignore[arg-type]
    )

    restored = service.restore(account_id="user@example.com", password="secret")

    assert restored is None


def test_restore_builds_endpoint_when_payload_present():
    payload = {"webservices": {"findme": {"url": "https://findme.test"}}}
    store = FakeStore(payload=payload)
    factory = FakeFactory()
    service = ServiceEndpointRestoreService(
        store=store,  # type: ignore[arg-type]
        endpoint_factory=factory,  # type: ignore[arg-type]
    )

    restored = service.restore(account_id="user@example.com", password="secret")

    assert restored == {"endpoint": True}
    assert store.calls == ["user@example.com"]
    assert factory.calls == [("user@example.com", "secret", payload)]
