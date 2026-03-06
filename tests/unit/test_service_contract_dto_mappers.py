from __future__ import annotations

from pydantic import TypeAdapter

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
from pyicloud.adapters.services.mappers.account import (
    map_account_device,
    map_account_family_member,
    map_account_storage,
)
from pyicloud.adapters.services.mappers.calendar import map_calendar, map_calendar_event, map_calendar_event_detail
from pyicloud.adapters.services.mappers.contacts import map_contact
from pyicloud.adapters.services.mappers.devices import map_device_location, map_device_snapshot, map_device_status
from pyicloud.adapters.services.mappers.drive import map_drive_node
from pyicloud.adapters.services.mappers.photos import map_photo_album, map_photo_asset
from pyicloud.adapters.services.mappers.reminders import map_reminder_collections
from pyicloud.adapters.services.mappers.ubiquity import map_ubiquity_node
from pyicloud.domain import (
    AccountDeviceDTO,
    AccountFamilyMemberDTO,
    AccountStorageDTO,
    CalendarDTO,
    CalendarEventDetailDTO,
    CalendarEventDTO,
    ContactDTO,
    DeviceRecordDTO,
    DriveNodeDTO,
    PhotoAlbumDTO,
    PhotoAssetDTO,
    ReminderListsDTO,
    UbiquityNodeDTO,
)


def test_device_mappers_validate_against_device_record_dto() -> None:
    device_adapter = TypeAdapter(DeviceRecordDTO)

    snapshot = map_device_snapshot(DeviceSnapshot(device_id="dev-1", payload={"id": "dev-1", "name": "iPhone"}))
    assert device_adapter.validate_python(snapshot)["id"] == "dev-1"

    location = map_device_location(DeviceLocationView(payload={"latitude": 1.23, "longitude": 2.34}))
    assert device_adapter.validate_python(location)["latitude"] == 1.23

    status = map_device_status(
        DeviceStatusView(
            device_id="dev-1",
            name="iPhone",
            device_class="iPhone",
            battery_level=0.87,
            battery_status="Charging",
        )
    )
    validated = device_adapter.validate_python(status)
    assert validated["batteryLevel"] == 0.87
    assert validated["batteryStatus"] == "Charging"


def test_account_mappers_validate_against_account_dtos() -> None:
    device_adapter = TypeAdapter(AccountDeviceDTO)
    family_adapter = TypeAdapter(AccountFamilyMemberDTO)
    storage_adapter = TypeAdapter(AccountStorageDTO)

    account_device = map_account_device(AccountDeviceView(payload={"id": "dev-1", "name": "iPhone"}))
    assert device_adapter.validate_python(account_device)["id"] == "dev-1"

    family_member = map_account_family_member(FamilyMemberView(payload={"fullName": "User Test"}))
    assert family_adapter.validate_python(family_member)["fullName"] == "User Test"

    storage_view = AccountStorageView(
        usage=StorageUsageView(
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
        ),
        usages_by_media={
            "photos": MediaUsageView(key="photos", label="Photos", color="#fff", usage_in_bytes=10),
        },
    )
    storage = map_account_storage(storage_view)
    validated_storage = storage_adapter.validate_python(storage)
    assert validated_storage["usage"]["total_storage_in_bytes"] == 6
    assert validated_storage["usages_by_media"]["photos"]["usage_in_bytes"] == 10


def test_drive_mapper_validates_against_drive_node_dto() -> None:
    adapter = TypeAdapter(DriveNodeDTO)
    node = map_drive_node(
        DriveNodeView(
            path="/Documents",
            name="Documents",
            node_type="folder",
            size=None,
            date_changed="2026-03-06T10:00:00Z",
            date_modified="2026-03-06T10:05:00Z",
            date_last_open=None,
            children=[{"name": "notes.txt", "type": "file"}],
        )
    )
    validated = adapter.validate_python(node)
    assert validated["path"] == "/Documents"
    assert validated["children"][0]["name"] == "notes.txt"


def test_secondary_domain_mappers_validate_against_service_contract_dtos() -> None:
    calendar_adapter = TypeAdapter(CalendarDTO)
    event_adapter = TypeAdapter(CalendarEventDTO)
    event_detail_adapter = TypeAdapter(CalendarEventDetailDTO)
    contact_adapter = TypeAdapter(ContactDTO)
    reminder_lists_adapter = TypeAdapter(ReminderListsDTO)
    photo_album_adapter = TypeAdapter(PhotoAlbumDTO)
    photo_asset_adapter = TypeAdapter(PhotoAssetDTO)
    ubiquity_adapter = TypeAdapter(UbiquityNodeDTO)

    calendar = map_calendar(CalendarView(payload={"guid": "cal-1", "title": "Work"}))
    assert calendar_adapter.validate_python(calendar)["guid"] == "cal-1"

    event = map_calendar_event(CalendarEventView(payload={"guid": "event-1", "calendarGuid": "cal-1"}))
    assert event_adapter.validate_python(event)["calendarGuid"] == "cal-1"

    event_detail = map_calendar_event_detail(
        CalendarEventDetailView(payload={"guid": "event-1", "calendarGuid": "cal-1", "notes": "Discuss Q2"})
    )
    assert event_detail_adapter.validate_python(event_detail)["notes"] == "Discuss Q2"

    contact = map_contact(
        ContactView(payload={"displayName": "Inean User", "phones": [{"label": "mobile", "value": "+34123"}]})
    )
    assert contact_adapter.validate_python(contact)["displayName"] == "Inean User"

    reminder_lists = map_reminder_collections(
        [
            ReminderCollectionView(
                title="Inbox",
                reminders=[ReminderView(payload={"title": "Task 1"}), ReminderView(payload={"title": "Task 2"})],
            )
        ]
    )
    assert reminder_lists_adapter.validate_python(reminder_lists)["Inbox"][1]["title"] == "Task 2"

    album = map_photo_album(PhotoAlbumView(name="Favorites", count=3))
    assert photo_album_adapter.validate_python(album)["count"] == 3

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
    validated_asset = photo_asset_adapter.validate_python(asset)
    assert validated_asset["id"] == "photo-1"
    assert validated_asset["versions"]["original"]["type"] == "image/jpeg"

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
    validated_tree = ubiquity_adapter.validate_python(tree)
    assert validated_tree["path"] == "/"
    assert validated_tree["children"][0]["name"] == "Documents"
