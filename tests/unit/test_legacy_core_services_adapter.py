from __future__ import annotations

from datetime import UTC, datetime
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


class _FakeStreamResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ANN001, ANN201
        return None

    def iter_raw(self):
        yield self._payload


class _FakePhotoAsset:
    def __init__(self, asset_id: str, filename: str, payload: bytes):
        self.id = asset_id
        self.filename = filename
        self.size = len(payload)
        self.created = datetime(2026, 3, 4, 10, 0, tzinfo=UTC)
        self.dimensions = (1920, 1080)
        self.versions = {
            "original": {
                "filename": filename,
                "width": 1920,
                "height": 1080,
                "size": len(payload),
                "type": "image/jpeg",
            }
        }
        self._payload = payload

    def download(self, version: str = "original", **kwargs):  # noqa: ARG002
        if version not in self.versions:
            return None
        return _FakeStreamResponse(self._payload)


class _FakePhotoAlbum:
    def __init__(self, assets: list[_FakePhotoAsset]):
        self._assets = assets

    def __len__(self) -> int:
        return len(self._assets)

    @property
    def photos(self):
        return iter(self._assets)


class _FakeUbiquityNode:
    def __init__(
        self,
        *,
        item_id: int,
        name: str,
        node_type: str,
        size: int | None,
        modified: datetime | None,
        children: list[_FakeUbiquityNode] | None = None,
        payload: bytes = b"",
    ):
        self.item_id = item_id
        self.name = name
        self.type = node_type
        self.size = size
        self.modified = modified
        self._children = children or []
        self._payload = payload

    def get_children(self):
        return list(self._children)

    def open(self, **kwargs):  # noqa: ARG002
        return _FakeStreamResponse(self._payload)

    def __getitem__(self, key: str):
        for child in self._children:
            if child.name == key:
                return child
        raise KeyError(key)


def test_legacy_core_services_adapter_photo_operations(monkeypatch: pytest.MonkeyPatch):
    asset_1 = _FakePhotoAsset("photo-1", "beach.jpg", b"photo-1-bytes")
    asset_2 = _FakePhotoAsset("photo-2", "sunset.jpg", b"photo-2-bytes")
    photos = SimpleNamespace(
        albums={
            "All Photos": _FakePhotoAlbum([asset_1, asset_2]),
            "Favorites": _FakePhotoAlbum([asset_2]),
        }
    )
    services = SimpleNamespace(photos=photos)

    adapter = legacy_core.LegacyCoreServicesAdapter(
        session_store=SimpleNamespace(load=lambda account_id: {}),
        endpoint_factory=SimpleNamespace(),
    )
    monkeypatch.setattr(adapter, "_services", lambda username: services)

    albums = adapter.list_albums(username="success@example.com")
    assert albums == [{"name": "All Photos", "count": 2}, {"name": "Favorites", "count": 1}]

    assets = adapter.list_assets(username="success@example.com", album="All Photos", limit=1, offset=1)
    assert [item["id"] for item in assets] == ["photo-2"]

    metadata = adapter.asset_metadata(username="success@example.com", album="All Photos", asset_id="photo-1")
    assert metadata["filename"] == "beach.jpg"
    assert metadata["versions"]["original"]["type"] == "image/jpeg"

    content = adapter.asset_content(username="success@example.com", album="All Photos", asset_id="photo-1")
    assert content == b"photo-1-bytes"

    with pytest.raises(KeyError, match="Photo version not found"):
        adapter.asset_content(
            username="success@example.com",
            album="All Photos",
            asset_id="photo-1",
            version="missing",
        )


def test_legacy_core_services_adapter_ubiquity_operations(monkeypatch: pytest.MonkeyPatch):
    shared = _FakeUbiquityNode(
        item_id=102,
        name="shared.txt",
        node_type="file",
        size=14,
        modified=datetime(2026, 3, 4, 10, 5, tzinfo=UTC),
        payload=b"shared-content",
    )
    documents = _FakeUbiquityNode(
        item_id=101,
        name="Documents",
        node_type="folder",
        size=None,
        modified=datetime(2026, 3, 4, 10, 0, tzinfo=UTC),
        children=[shared],
    )
    notes = _FakeUbiquityNode(
        item_id=103,
        name="Notes",
        node_type="folder",
        size=None,
        modified=datetime(2026, 3, 4, 9, 0, tzinfo=UTC),
    )
    root = _FakeUbiquityNode(
        item_id=0,
        name="",
        node_type="folder",
        size=None,
        modified=None,
        children=[documents, notes],
    )
    services = SimpleNamespace(files=root)

    adapter = legacy_core.LegacyCoreServicesAdapter(
        session_store=SimpleNamespace(load=lambda account_id: {}),
        endpoint_factory=SimpleNamespace(),
    )
    monkeypatch.setattr(adapter, "_services", lambda username: services)

    tree = adapter.ubiquity_tree(username="success@example.com", path="/")
    assert [child["name"] for child in tree["children"]] == ["Documents", "Notes"]

    metadata = adapter.ubiquity_file_metadata(username="success@example.com", path="/Documents/shared.txt")
    assert metadata["type"] == "file"
    assert metadata["name"] == "shared.txt"

    content = adapter.ubiquity_file_content(username="success@example.com", path="/Documents/shared.txt")
    assert content == b"shared-content"

    with pytest.raises(KeyError, match="Ubiquity path is not a file"):
        adapter.ubiquity_file_content(username="success@example.com", path="/Documents")
