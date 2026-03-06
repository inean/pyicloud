from __future__ import annotations

from pydantic import TypeAdapter

from pyicloud.adapters.services.clients.account import (
    AccountDeviceView,
    AccountStorageView,
    FamilyMemberView,
    MediaUsageView,
    StorageUsageView,
)
from pyicloud.adapters.services.clients.devices import DeviceLocationView, DeviceSnapshot, DeviceStatusView
from pyicloud.adapters.services.clients.drive import DriveNodeView
from pyicloud.adapters.services.mappers.account import (
    map_account_device,
    map_account_family_member,
    map_account_storage,
)
from pyicloud.adapters.services.mappers.devices import map_device_location, map_device_snapshot, map_device_status
from pyicloud.adapters.services.mappers.drive import map_drive_node
from pyicloud.domain import (
    AccountDeviceDTO,
    AccountFamilyMemberDTO,
    AccountStorageDTO,
    DeviceRecordDTO,
    DriveNodeDTO,
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
