from __future__ import annotations

from pyicloud.adapters.services.clients.account import (
    AccountDeviceView,
    AccountStorageView,
    FamilyMemberView,
    MediaUsageView,
    StorageUsageView,
)
from pyicloud.adapters.services.clients.calendar import CalendarEventDetailView, CalendarEventView, CalendarView
from pyicloud.adapters.services.clients.contacts import ContactView
from pyicloud.adapters.services.clients.devices import DeviceLocationView, DeviceSnapshot, DeviceStatusView
from pyicloud.adapters.services.clients.drive import DriveNodeView
from pyicloud.adapters.services.clients.photos import PhotoAlbumView, PhotoAssetView, PhotoVersionView
from pyicloud.adapters.services.clients.reminders import ReminderCollectionView, ReminderView
from pyicloud.adapters.services.clients.ubiquity import UbiquityNodeView
from pyicloud.adapters.services.mappers import (
    map_account_device,
    map_account_family_member,
    map_account_storage,
    map_calendar,
    map_calendar_event,
    map_calendar_event_detail,
    map_contact,
    map_device_location,
    map_device_snapshot,
    map_device_status,
    map_drive_node,
    map_photo_album,
    map_photo_asset,
    map_reminder_collections,
    map_ubiquity_node,
)


def test_device_mappers() -> None:
    snapshot = DeviceSnapshot(device_id="dev-1", payload={"id": "dev-1", "name": "Phone"})
    location = DeviceLocationView(payload={"latitude": 1.0})
    status = DeviceStatusView(
        device_id="dev-1",
        name="Phone",
        device_class="iPhone",
        battery_level=0.9,
        battery_status="Charging",
    )

    assert map_device_snapshot(snapshot)["id"] == "dev-1"
    assert map_device_location(location)["latitude"] == 1.0
    assert map_device_status(status)["deviceClass"] == "iPhone"


def test_account_mappers() -> None:
    usage = StorageUsageView(
        comp_storage_in_bytes=1,
        used_storage_in_bytes=2,
        used_storage_in_percent=3.0,
        available_storage_in_bytes=4,
        available_storage_in_percent=5.0,
        total_storage_in_bytes=6,
        commerce_storage_in_bytes=7,
        quota_over=False,
        quota_tier_max=False,
        quota_almost_full=False,
        quota_paid=True,
    )
    media = {"drive": MediaUsageView(key="drive", label="Drive", color="#fff", usage_in_bytes=10)}
    storage = AccountStorageView(usage=usage, usages_by_media=media)

    assert map_account_device(AccountDeviceView(payload={"id": "dev-1"}))["id"] == "dev-1"
    assert map_account_family_member(FamilyMemberView(payload={"fullName": "User"}))["fullName"] == "User"
    assert map_account_storage(storage)["usage"]["total_storage_in_bytes"] == 6


def test_drive_mapper() -> None:
    node = DriveNodeView(
        path="/Docs/file.txt",
        name="file.txt",
        node_type="file",
        size=11,
        date_changed=None,
        date_modified=None,
        date_last_open=None,
        children=[{"name": "child", "type": "file"}],
    )
    mapped = map_drive_node(node)
    assert mapped["path"] == "/Docs/file.txt"
    assert mapped["children"] == [{"name": "child", "type": "file"}]


def test_calendar_contacts_and_reminders_mappers() -> None:
    assert map_calendar(CalendarView(payload={"guid": "cal-1"}))["guid"] == "cal-1"
    assert map_calendar_event(CalendarEventView(payload={"guid": "evt-1"}))["guid"] == "evt-1"
    detail = map_calendar_event_detail(CalendarEventDetailView(payload={"guid": "evt-1", "title": "Review"}))
    assert detail["title"] == "Review"
    assert map_contact(ContactView(payload={"displayName": "User"}))["displayName"] == "User"

    collections = map_reminder_collections(
        [
            ReminderCollectionView(
                title="Inbox",
                reminders=[ReminderView(payload={"title": "Task 1"}), ReminderView(payload={"title": "Task 2"})],
            )
        ]
    )
    assert collections == {"Inbox": [{"title": "Task 1"}, {"title": "Task 2"}]}


def test_photo_and_ubiquity_mappers() -> None:
    album = map_photo_album(PhotoAlbumView(name="Favorites", count=3))
    assert album == {"name": "Favorites", "count": 3}

    asset = map_photo_asset(
        PhotoAssetView(
            asset_id="photo-1",
            album="Favorites",
            filename="beach.jpg",
            size=123,
            created="2026-03-05T10:00:00+00:00",
            width=1920,
            height=1080,
            versions={
                "original": PhotoVersionView(
                    filename="beach.jpg",
                    width=1920,
                    height=1080,
                    size=123,
                    content_type="image/jpeg",
                )
            },
        )
    )
    assert asset["id"] == "photo-1"
    assert asset["versions"]["original"]["type"] == "image/jpeg"

    tree = map_ubiquity_node(
        UbiquityNodeView(
            path="/",
            item_id=0,
            name="",
            node_type="folder",
            size=None,
            modified=None,
            children=[
                UbiquityNodeView(
                    path="/Documents",
                    item_id=1,
                    name="Documents",
                    node_type="folder",
                    size=None,
                    modified="2026-03-05T12:00:00+00:00",
                )
            ],
        )
    )
    assert tree["path"] == "/"
    assert tree["children"] == [
        {
            "path": "/Documents",
            "item_id": 1,
            "name": "Documents",
            "type": "folder",
            "size": None,
            "modified": "2026-03-05T12:00:00+00:00",
        }
    ]
