from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from pyicloud.adapters.services import (
    AccountServiceAdapter,
    CalendarServiceAdapter,
    ContactsServiceAdapter,
    DevicesServiceAdapter,
    DriveServiceAdapter,
    LegacyCoreServicesAdapter,
    RemindersServiceAdapter,
    build_core_adapter_bundle,
    legacy_core,
)
from pyicloud.adapters.services import (
    runtime as legacy_runtime,
)


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

    monkeypatch.setattr(legacy_runtime, "PyiCloudServices", FakePyiCloudServices)
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


@pytest.mark.asyncio
async def test_legacy_core_services_adapter_photo_operations(monkeypatch: pytest.MonkeyPatch):
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
    monkeypatch.setattr(adapter._runtime, "services", lambda username: services)

    albums = await adapter.list_albums(username="success@example.com")
    assert albums == [{"name": "All Photos", "count": 2}, {"name": "Favorites", "count": 1}]

    assets = await adapter.list_assets(username="success@example.com", album="All Photos", limit=1, offset=1)
    assert [item["id"] for item in assets] == ["photo-2"]

    metadata = await adapter.asset_metadata(username="success@example.com", album="All Photos", asset_id="photo-1")
    assert metadata["filename"] == "beach.jpg"
    assert metadata["versions"]["original"]["type"] == "image/jpeg"

    content = await adapter.asset_content(username="success@example.com", album="All Photos", asset_id="photo-1")
    assert content == b"photo-1-bytes"

    with pytest.raises(KeyError, match="Photo version not found"):
        await adapter.asset_content(
            username="success@example.com",
            album="All Photos",
            asset_id="photo-1",
            version="missing",
        )


@pytest.mark.asyncio
async def test_legacy_core_services_adapter_ubiquity_operations(monkeypatch: pytest.MonkeyPatch):
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
    monkeypatch.setattr(adapter._runtime, "services", lambda username: services)

    tree = await adapter.ubiquity_tree(username="success@example.com", path="/")
    assert [child["name"] for child in tree["children"]] == ["Documents", "Notes"]

    metadata = await adapter.ubiquity_file_metadata(username="success@example.com", path="/Documents/shared.txt")
    assert metadata["type"] == "file"
    assert metadata["name"] == "shared.txt"

    content = await adapter.ubiquity_file_content(username="success@example.com", path="/Documents/shared.txt")
    assert content == b"shared-content"

    with pytest.raises(KeyError, match="Ubiquity path is not a file"):
        await adapter.ubiquity_file_content(username="success@example.com", path="/Documents")


class _RuntimeStub:
    def __init__(self, services: Any):
        self._services = services

    def services(self, *, username: str):  # noqa: ARG002
        return self._services


class _DriveNode:
    def __init__(self, *, name: str, node_type: str = "file", payload: bytes = b""):
        self.name = name
        self.type = node_type
        self.size = len(payload)
        self.date_changed = None
        self.date_modified = None
        self.date_last_open = None
        self._payload = payload
        self._children: dict[str, _DriveNode] = {}

    def __getitem__(self, key: str):
        return self._children[key]

    def add_child(self, key: str, node: _DriveNode) -> None:
        self._children[key] = node

    def dir(self):
        return [{"name": node.name, "type": node.type} for node in self._children.values()]

    def open(self, stream: bool = True):  # noqa: ARG002
        return _FakeStreamResponse(self._payload)

    def mkdir(self, name: str):
        self._children[name] = _DriveNode(name=name, node_type="folder")

    def upload(self, fileobj):
        self._children[fileobj.name] = _DriveNode(name=fileobj.name, payload=fileobj.read())

    def rename(self, new_name: str):
        self.name = new_name

    def delete(self):
        self._payload = b""


@pytest.mark.asyncio
async def test_decomposed_adapters_cover_devices_account_drive_calendar_contacts_reminders():
    # Devices
    device_1 = {
        "id": "dev-1",
        "name": "iPhone",
    }

    class _Device(dict):
        def __init__(self):
            super().__init__(device_1)
            self.data = dict(device_1)

        def location(self):
            return {"lat": 1.0, "lon": 2.0}

        def status(self):
            return {"batteryLevel": 0.9}

        def play_sound(self, subject: str):  # noqa: ARG002
            return None

        def display_message(self, subject: str, message: str, sounds: bool):  # noqa: ARG002
            return None

        def lost_device(self, number: str, text: str, newpasscode: str):  # noqa: ARG002
            return None

    manager = {"dev-1": _Device()}

    # Account
    usage = SimpleNamespace(
        comp_storage_in_bytes=1,
        used_storage_in_bytes=2,
        used_storage_in_percent=3.0,
        available_storage_in_bytes=4,
        available_storage_in_percent=5.0,
        total_storage_in_bytes=6,
        commerce_storage_in_bytes=0,
        quota_over=False,
        quota_tier_max=False,
        quota_almost_full=False,
        quota_paid=True,
    )
    media = SimpleNamespace(key="drive", label="Drive", color="#fff", usage_in_bytes=9)
    storage = SimpleNamespace(usage=usage, usages_by_media={"drive": media})
    account = SimpleNamespace(
        devices=[{"id": "dev-1"}],
        family=[SimpleNamespace(_attrs={"fullName": "User"})],
        storage=storage,
    )

    # Drive
    root = _DriveNode(name="/", node_type="folder")
    docs = _DriveNode(name="Documents", node_type="folder")
    report = _DriveNode(name="report.txt", payload=b"report-bytes")
    docs.add_child("report.txt", report)
    root.add_child("Documents", docs)

    # Calendar / Contacts / Reminders
    calendar = SimpleNamespace(
        calendars=lambda: [{"guid": "cal-1"}],
        events=lambda from_dt=None, to_dt=None: [{"guid": "event-1"}],  # noqa: ARG005
        get_event_detail=lambda pguid, guid: {"pguid": pguid, "guid": guid},
    )
    contacts = SimpleNamespace(all=lambda: [{"displayName": "User"}])
    reminders = SimpleNamespace(
        lists={"Inbox": [{"title": "Task"}]},
        post=lambda **kwargs: True,  # noqa: ARG005
    )

    services = SimpleNamespace(
        devices=manager,
        account=account,
        drive=root,
        calendar=calendar,
        contacts=contacts,
        reminders=reminders,
    )
    runtime = _RuntimeStub(services)

    devices_adapter = DevicesServiceAdapter(runtime=runtime)
    account_adapter = AccountServiceAdapter(runtime=runtime)
    drive_adapter = DriveServiceAdapter(runtime=runtime)
    calendar_adapter = CalendarServiceAdapter(runtime=runtime)
    contacts_adapter = ContactsServiceAdapter(runtime=runtime)
    reminders_adapter = RemindersServiceAdapter(runtime=runtime)

    assert (await devices_adapter.list_devices(username="user@example.com"))[0]["id"] == "dev-1"
    assert (await account_adapter.account_storage(username="user@example.com"))["usage"]["total_storage_in_bytes"] == 6
    assert (
        await drive_adapter.file_content(username="user@example.com", path="/Documents/report.txt") == b"report-bytes"
    )
    assert (await calendar_adapter.events(username="user@example.com"))[0]["guid"] == "event-1"
    assert (await contacts_adapter.all_contacts(username="user@example.com"))[0]["displayName"] == "User"
    assert await reminders_adapter.create_reminder(username="user@example.com", title="Task")


def test_build_core_adapter_bundle_shares_runtime_instance():
    bundle = build_core_adapter_bundle(
        session_store=SimpleNamespace(
            load=lambda username: {"webservices": {"findme": {"url": "https://example.test"}}}
        ),
        endpoint_factory=SimpleNamespace(from_payload=lambda **kwargs: object()),  # noqa: ARG005
    )

    assert type(bundle.devices) is DevicesServiceAdapter
    assert type(bundle.accounts) is AccountServiceAdapter
    assert type(bundle.drive) is DriveServiceAdapter
    assert type(bundle.calendars) is CalendarServiceAdapter
    assert type(bundle.contacts) is ContactsServiceAdapter
    assert type(bundle.reminders) is RemindersServiceAdapter
    assert isinstance(LegacyCoreServicesAdapter(), legacy_core.LegacyCoreServicesAdapter)
    assert bundle.devices._runtime is bundle.accounts._runtime is bundle.drive._runtime
