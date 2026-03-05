from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from pyicloud.adapters.services.clients.calendar import LegacyCalendarClient
from pyicloud.adapters.services.clients.common import Pagination, TimeRangeFilter
from pyicloud.adapters.services.clients.contacts import LegacyContactsClient
from pyicloud.adapters.services.clients.photos import LegacyPhotosClient
from pyicloud.adapters.services.clients.reminders import LegacyRemindersClient
from pyicloud.adapters.services.clients.ubiquity import LegacyUbiquityClient
from pyicloud.adapters.services.content import (
    PhotoBinaryContentAdapter,
    StreamingBinaryContentAdapter,
    UbiquityBinaryContentAdapter,
)


class _RuntimeStub:
    def __init__(self, services):
        self._services = services

    def services(self, *, username: str):  # noqa: ARG002
        return self._services


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
    def __init__(self, *, asset_id: str, filename: str, payload: bytes):
        self.id = asset_id
        self.filename = filename
        self.size = len(payload)
        self.created = datetime(2026, 3, 5, 12, 0, tzinfo=UTC)
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

    def download(self, *, version: str = "original", stream: bool = True):  # noqa: ARG002
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
        payload: bytes = b"",
        children: list[_FakeUbiquityNode] | None = None,
    ):
        self.item_id = item_id
        self.name = name
        self.type = node_type
        self.size = size
        self.modified = datetime(2026, 3, 5, 12, 30, tzinfo=UTC)
        self._payload = payload
        self._children = children or []

    def __getitem__(self, key: str):
        for child in self._children:
            if child.name == key:
                return child
        raise KeyError(key)

    def get_children(self):
        return list(self._children)

    def open(self, stream: bool = True):  # noqa: ARG002
        return _FakeStreamResponse(self._payload)


def test_legacy_calendar_client_supports_range_and_pagination() -> None:
    observed: dict[str, datetime | None] = {}
    calendar = SimpleNamespace(
        calendars=lambda: [{"guid": "cal-1"}, {"guid": "cal-2"}],
        events=lambda from_dt=None, to_dt=None: _capture_range(observed, from_dt, to_dt),
        get_event_detail=lambda pguid, guid: {"calendarGuid": pguid, "eventGuid": guid},
    )
    runtime = _RuntimeStub(SimpleNamespace(calendar=calendar))
    client = LegacyCalendarClient(runtime=runtime, username="user@example.com")

    calendars = client.calendars(pagination=Pagination(limit=1, offset=1))
    assert [item.payload["guid"] for item in calendars] == ["cal-2"]

    from_dt = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)
    to_dt = datetime(2026, 1, 31, 23, 59, tzinfo=UTC)
    events = client.events(
        time_range=TimeRangeFilter(from_dt=from_dt, to_dt=to_dt),
        pagination=Pagination(limit=1, offset=1),
    )
    assert observed == {"from_dt": from_dt, "to_dt": to_dt}
    assert [item.payload["guid"] for item in events] == ["event-2"]

    detail = client.event_detail(calendar_guid="cal-1", event_guid="event-1")
    assert detail.payload == {"calendarGuid": "cal-1", "eventGuid": "event-1"}


def _capture_range(
    observed: dict[str, datetime | None],
    from_dt: datetime | None,
    to_dt: datetime | None,
):
    observed["from_dt"] = from_dt
    observed["to_dt"] = to_dt
    return [{"guid": "event-1"}, {"guid": "event-2"}]


def test_legacy_contacts_client_supports_pagination() -> None:
    contacts = SimpleNamespace(all=lambda: [{"name": "A"}, {"name": "B"}, {"name": "C"}])
    runtime = _RuntimeStub(SimpleNamespace(contacts=contacts))
    client = LegacyContactsClient(runtime=runtime, username="user@example.com")

    paged = client.all_contacts(pagination=Pagination(limit=2, offset=1))
    assert [item.payload["name"] for item in paged] == ["B", "C"]


def test_legacy_reminders_client_collections_and_create() -> None:
    calls: list[dict[str, object]] = []

    def _post(**kwargs):
        calls.append(kwargs)
        return True

    reminders = SimpleNamespace(
        lists={
            "Inbox": [{"title": "Task 1"}],
            "Work": [{"title": "Task 2"}],
        },
        post=_post,
    )
    runtime = _RuntimeStub(SimpleNamespace(reminders=reminders))
    client = LegacyRemindersClient(runtime=runtime, username="user@example.com")

    collections = client.collections(pagination=Pagination(limit=1, offset=1))
    assert len(collections) == 1
    assert collections[0].title == "Work"
    assert collections[0].reminders[0].payload["title"] == "Task 2"

    created = client.create_reminder(title="New", description="Desc", collection="Inbox")
    assert created is True
    assert calls == [{"title": "New", "description": "Desc", "collection": "Inbox", "due_date": None}]


def test_legacy_photos_client_albums_assets_metadata_and_content() -> None:
    photo_1 = _FakePhotoAsset(asset_id="photo-1", filename="beach.jpg", payload=b"photo-1")
    photo_2 = _FakePhotoAsset(asset_id="photo-2", filename="sunset.jpg", payload=b"photo-2")
    photos = SimpleNamespace(
        albums={
            "All Photos": _FakePhotoAlbum([photo_1, photo_2]),
            "Favorites": _FakePhotoAlbum([photo_2]),
        }
    )
    runtime = _RuntimeStub(SimpleNamespace(photos=photos))
    client = LegacyPhotosClient(runtime=runtime, username="user@example.com")

    albums = client.albums()
    assert [(item.name, item.count) for item in albums] == [("All Photos", 2), ("Favorites", 1)]

    assets = client.assets(album="All Photos", pagination=Pagination(limit=1, offset=1))
    assert [item.asset_id for item in assets] == ["photo-2"]

    metadata = client.asset_metadata(asset_id="photo-1", album="All Photos")
    assert metadata.filename == "beach.jpg"
    assert metadata.versions["original"].content_type == "image/jpeg"

    assert client.asset_content(asset_id="photo-1", album="All Photos", version="original") == b"photo-1"
    with pytest.raises(KeyError, match="Photo version not found"):
        client.asset_content(asset_id="photo-1", album="All Photos", version="missing")
    with pytest.raises(KeyError, match="Photo album not found"):
        client.assets(album="Missing")


def test_legacy_ubiquity_client_tree_metadata_and_content() -> None:
    shared = _FakeUbiquityNode(item_id=2, name="shared.txt", node_type="file", size=6, payload=b"shared")
    docs = _FakeUbiquityNode(item_id=1, name="Documents", node_type="folder", size=None, children=[shared])
    notes = _FakeUbiquityNode(item_id=3, name="Notes", node_type="folder", size=None)
    root = _FakeUbiquityNode(item_id=0, name="", node_type="folder", size=None, children=[docs, notes])
    runtime = _RuntimeStub(SimpleNamespace(files=root))
    client = LegacyUbiquityClient(runtime=runtime, username="user@example.com")

    tree = client.tree(path="/", pagination=Pagination(limit=1, offset=1))
    assert [item.name for item in tree.children or []] == ["Notes"]

    metadata = client.metadata(path="/Documents/shared.txt")
    assert metadata.node_type == "file"
    assert metadata.name == "shared.txt"

    assert client.content(path="/Documents/shared.txt") == b"shared"
    with pytest.raises(KeyError, match="not a file"):
        client.content(path="/Documents")


def test_binary_content_adapters_handle_stream_and_validation() -> None:
    stream = StreamingBinaryContentAdapter()
    assert stream.read_stream(_FakeStreamResponse(b"payload")) == b"payload"

    photo = _FakePhotoAsset(asset_id="photo-1", filename="beach.jpg", payload=b"photo")
    photo_adapter = PhotoBinaryContentAdapter(stream_reader=stream)
    assert photo_adapter.download(asset=photo, version="original") == b"photo"
    with pytest.raises(KeyError, match="Photo version not found"):
        photo_adapter.download(asset=photo, version="missing")

    file_node = _FakeUbiquityNode(item_id=1, name="doc.txt", node_type="file", size=7, payload=b"content")
    folder_node = _FakeUbiquityNode(item_id=2, name="Docs", node_type="folder", size=None)
    ubiquity_adapter = UbiquityBinaryContentAdapter(stream_reader=stream)
    assert ubiquity_adapter.read_file(node=file_node) == b"content"
    with pytest.raises(KeyError, match="not a file"):
        ubiquity_adapter.read_file(node=folder_node)
