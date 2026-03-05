from __future__ import annotations

from types import SimpleNamespace

from pyicloud.adapters.services.clients import (
    LegacyAccountClient,
    LegacyDevicesClient,
    LegacyDriveClient,
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


class _FakeDevice(dict):
    def __init__(self, device_id: str):
        super().__init__({"id": device_id, "name": "Device"})
        self.data = {"id": device_id, "name": "Device"}
        self.last_action = None

    def location(self):
        return {"latitude": 1.0}

    def status(self):
        return {"name": "Device", "deviceClass": "iPhone", "batteryLevel": 0.8, "batteryStatus": "Charging"}

    def play_sound(self, subject: str):
        self.last_action = ("play_sound", subject)

    def display_message(self, subject: str, message: str, sounds: bool):
        self.last_action = ("display_message", subject, message, sounds)

    def lost_device(self, number: str, text: str, newpasscode: str):
        self.last_action = ("lost_mode", number, text, newpasscode)


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
        self.last_action = None

    def __getitem__(self, key: str):
        return self._children[key]

    def add_child(self, key: str, node: _DriveNode) -> None:
        self._children[key] = node

    def dir(self):
        return [{"name": node.name, "type": node.type} for node in self._children.values()]

    def open(self, stream: bool = True):  # noqa: ARG002
        return _FakeStreamResponse(self._payload)

    def mkdir(self, name: str):
        self.last_action = ("mkdir", name)

    def upload(self, fileobj):
        self.last_action = ("upload", fileobj.name, fileobj.read())

    def rename(self, new_name: str):
        self.last_action = ("rename", new_name)

    def delete(self):
        self.last_action = ("delete",)


def test_legacy_devices_client_list_and_actions() -> None:
    device = _FakeDevice("dev-1")
    runtime = _RuntimeStub(SimpleNamespace(devices={"dev-1": device}))
    client = LegacyDevicesClient(runtime=runtime, username="user@example.com")

    snapshots = client.list_devices()
    assert snapshots[0].device_id == "dev-1"
    assert snapshots[0].payload["name"] == "Device"
    assert client.location(device_id="dev-1").payload["latitude"] == 1.0
    assert client.status(device_id="dev-1").device_class == "iPhone"

    client.play_sound(device_id="dev-1", subject="Find")
    assert device.last_action == ("play_sound", "Find")


def test_legacy_account_client_storage_mapping() -> None:
    usage = SimpleNamespace(
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
    media = SimpleNamespace(key="photos", label="Photos", color="#aaa", usage_in_bytes=10)
    account = SimpleNamespace(
        devices=[{"id": "dev-1"}],
        family=[SimpleNamespace(_attrs={"fullName": "User"})],
        storage=SimpleNamespace(usage=usage, usages_by_media={"photos": media}),
    )
    runtime = _RuntimeStub(SimpleNamespace(account=account))
    client = LegacyAccountClient(runtime=runtime, username="user@example.com")

    storage = client.storage()
    assert storage.usage.total_storage_in_bytes == 6
    assert storage.usages_by_media["photos"].usage_in_bytes == 10
    assert client.devices()[0].payload["id"] == "dev-1"
    assert client.family()[0].payload["fullName"] == "User"


def test_legacy_drive_client_tree_metadata_content_and_mutations() -> None:
    root = _DriveNode(name="/", node_type="folder")
    docs = _DriveNode(name="Documents", node_type="folder")
    report = _DriveNode(name="report.txt", payload=b"payload")
    docs.add_child("report.txt", report)
    root.add_child("Documents", docs)

    runtime = _RuntimeStub(SimpleNamespace(drive=root))
    client = LegacyDriveClient(runtime=runtime, username="user@example.com")

    tree = client.tree(path="/")
    assert tree.path == "/"
    assert tree.children == [{"name": "Documents", "type": "folder"}]

    metadata = client.metadata(path="/Documents/report.txt")
    assert metadata.name == "report.txt"
    assert client.content(path="/Documents/report.txt") == b"payload"

    client.create_folder(parent_path="/Documents", name="Archive")
    assert docs.last_action == ("mkdir", "Archive")
    client.upload_file(parent_path="/Documents", filename="new.txt", content=b"hello")
    assert docs.last_action == ("upload", "new.txt", b"hello")
    client.rename_node(path="/Documents/report.txt", new_name="renamed.txt")
    assert report.last_action == ("rename", "renamed.txt")
    client.delete_node(path="/Documents/report.txt")
    assert report.last_action == ("delete",)
