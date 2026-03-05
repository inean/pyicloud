from __future__ import annotations

from pyicloud.adapters.services.clients.account import (
    AccountDeviceView,
    AccountStorageView,
    FamilyMemberView,
    MediaUsageView,
    StorageUsageView,
)
from pyicloud.adapters.services.clients.devices import DeviceLocationView, DeviceSnapshot, DeviceStatusView
from pyicloud.adapters.services.clients.drive import DriveNodeView
from pyicloud.adapters.services.mappers import (
    map_account_device,
    map_account_family_member,
    map_account_storage,
    map_device_location,
    map_device_snapshot,
    map_device_status,
    map_drive_node,
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
