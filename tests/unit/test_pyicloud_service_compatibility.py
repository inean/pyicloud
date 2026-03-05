from __future__ import annotations

from types import SimpleNamespace

import pytest

import pyicloud.service as service_module
from pyicloud import PyiCloudService


class _FakeDevicesPort:
    def __init__(self):
        self.calls: list[tuple] = []

    def list_devices(self, *, username: str):
        self.calls.append(("list_devices", username))
        return [{"id": "dev-1", "name": "Phone"}]

    def location(self, *, username: str, device_id: str):
        self.calls.append(("location", username, device_id))
        return {"latitude": 1.0, "longitude": 2.0}

    def status(self, *, username: str, device_id: str):
        self.calls.append(("status", username, device_id))
        return {"id": device_id, "batteryStatus": "Charging"}

    def play_sound(self, *, username: str, device_id: str, subject: str):
        self.calls.append(("play_sound", username, device_id, subject))

    def display_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool):
        self.calls.append(("display_message", username, device_id, subject, message, sounds))

    def lost_mode(
        self,
        *,
        username: str,
        device_id: str,
        number: str,
        text: str,
        newpasscode: str,
    ):
        self.calls.append(("lost_mode", username, device_id, number, text, newpasscode))


def _fake_bundle():
    devices = _FakeDevicesPort()
    accounts = SimpleNamespace(
        account_devices=lambda username: [{"id": "acc-dev-1"}],  # noqa: ARG005
        account_family=lambda username: [{"fullName": "User"}],  # noqa: ARG005
        account_storage=lambda username: {"usage": {"total_storage_in_bytes": 1000}},  # noqa: ARG005
    )
    drive = SimpleNamespace(
        tree=lambda username, path: {"path": path},  # noqa: ARG005
        file_metadata=lambda username, path: {"path": path, "type": "file"},  # noqa: ARG005
        file_content=lambda username, path: b"drive-bytes",  # noqa: ARG005
        create_folder=lambda username, parent_path, name: None,  # noqa: ARG005
        upload_file=lambda username, parent_path, filename, content: None,  # noqa: ARG005
        rename_node=lambda username, path, new_name: None,  # noqa: ARG005
        delete_node=lambda username, path: None,  # noqa: ARG005
    )
    calendars = SimpleNamespace(
        calendars=lambda username: [{"guid": "cal-1"}],  # noqa: ARG005
        events=lambda username, from_dt=None, to_dt=None: [{"guid": "evt-1"}],  # noqa: ARG005
        event_detail=lambda username, calendar_guid, event_guid: {"guid": event_guid},  # noqa: ARG005
    )
    contacts = SimpleNamespace(all_contacts=lambda username: [{"displayName": "User"}])  # noqa: ARG005
    reminders = SimpleNamespace(
        reminder_lists=lambda username: {"Inbox": [{"title": "Task"}]},  # noqa: ARG005
        create_reminder=lambda username, title, description="", collection=None, due_date=None: True,  # noqa: ARG005
    )
    photos = SimpleNamespace(
        list_albums=lambda username: [{"name": "All Photos", "count": 1}],  # noqa: ARG005
        list_assets=lambda username, album, limit=100, offset=0: [{"id": "photo-1"}],  # noqa: ARG005
        asset_metadata=lambda username, asset_id, album="All Photos": {"id": asset_id},  # noqa: ARG005
        asset_content=lambda username, asset_id, album="All Photos", version="original": b"photo-bytes",  # noqa: ARG005
    )
    ubiquity = SimpleNamespace(
        ubiquity_tree=lambda username, path: {"path": path, "children": []},  # noqa: ARG005
        ubiquity_file_metadata=lambda username, path: {"path": path, "type": "file"},  # noqa: ARG005
        ubiquity_file_content=lambda username, path: b"ubiquity-bytes",  # noqa: ARG005
    )
    return SimpleNamespace(
        devices=devices,
        accounts=accounts,
        drive=drive,
        calendars=calendars,
        contacts=contacts,
        reminders=reminders,
        photos=photos,
        ubiquity=ubiquity,
    )


def _noop_restore_builder():
    return SimpleNamespace(restore=lambda account_id, password: object())  # noqa: ARG005


async def _noop_auth_runner(*, username: str, password: str, interactive: bool):  # noqa: ARG001
    return None


def _build_service(monkeypatch: pytest.MonkeyPatch):
    fake_bundle = _fake_bundle()
    build_calls: list[tuple[object, object]] = []

    def _fake_build(*, session_store, endpoint_factory):
        build_calls.append((session_store, endpoint_factory))
        return fake_bundle

    monkeypatch.setattr(service_module, "build_legacy_core_adapter_bundle", _fake_build)
    api = PyiCloudService(
        "user@example.com",
        "secret",
        _auth_runner=_noop_auth_runner,
        _restore_builder=_noop_restore_builder,
        _session_store=SimpleNamespace(load=lambda account_id: None),  # noqa: ARG005
        _endpoint_factory=SimpleNamespace(),
    )
    return api, fake_bundle, build_calls


def test_top_level_pyicloudservice_uses_adapter_composition(monkeypatch: pytest.MonkeyPatch):
    with pytest.deprecated_call(match="compatibility facade is deprecated"):
        api, _, build_calls = _build_service(monkeypatch)

    assert build_calls, "Expected adapter bundle builder to be used"
    policy = api.compatibility_policy()
    assert "supported" in policy
    assert "deprecated" in policy
    assert "removed" in policy
    assert api.list_devices()[0]["id"] == "dev-1"


def test_compat_device_surface_and_actions(monkeypatch: pytest.MonkeyPatch):
    with pytest.deprecated_call(match="compatibility facade is deprecated"):
        api, fake_bundle, _ = _build_service(monkeypatch)

    manager = api.devices
    assert manager.keys() == ["dev-1"]

    device = manager[0]
    assert device.data["name"] == "Phone"
    assert device.location()["latitude"] == 1.0
    assert api.iphone.status()["batteryStatus"] == "Charging"
    device.play_sound(subject="Find")
    device.display_message(subject="Notice", message="Hello", sounds=True)
    device.lost_device(number="+34123456789", text="Lost", newpasscode="1234")

    assert ("play_sound", "user@example.com", "dev-1", "Find") in fake_bundle.devices.calls
    assert ("display_message", "user@example.com", "dev-1", "Notice", "Hello", True) in fake_bundle.devices.calls
    assert ("lost_mode", "user@example.com", "dev-1", "+34123456789", "Lost", "1234") in fake_bundle.devices.calls


def test_deprecated_domain_attributes_warn_and_delegate(monkeypatch: pytest.MonkeyPatch):
    with pytest.deprecated_call(match="compatibility facade is deprecated"):
        api, _, _ = _build_service(monkeypatch)

    with pytest.deprecated_call(match="surface `account` is deprecated"):
        account = api.account
    assert account.devices[0]["id"] == "acc-dev-1"

    with pytest.deprecated_call(match="surface `drive` is deprecated"):
        drive = api.drive
    assert drive.tree(path="/")["path"] == "/"

    with pytest.deprecated_call(match="surface `photos` is deprecated"):
        photos = api.photos
    assert photos.albums[0]["name"] == "All Photos"

    with pytest.deprecated_call(match="surface `files` is deprecated"):
        files = api.files
    assert files.tree(path="/")["children"] == []


def test_unknown_surface_raises_guided_error(monkeypatch: pytest.MonkeyPatch):
    with pytest.deprecated_call(match="compatibility facade is deprecated"):
        api, _, _ = _build_service(monkeypatch)

    with pytest.raises(AttributeError, match="compatibility_policy"):
        _ = api.nonexistent_surface


@pytest.mark.asyncio
async def test_pyicloudservice_rejects_running_event_loop():
    with pytest.raises(RuntimeError, match="running event loop"):
        PyiCloudService(
            "user@example.com",
            "secret",
            _auth_runner=_noop_auth_runner,
            _restore_builder=_noop_restore_builder,
            _session_store=SimpleNamespace(load=lambda account_id: None),  # noqa: ARG005
            _endpoint_factory=SimpleNamespace(),
        )
