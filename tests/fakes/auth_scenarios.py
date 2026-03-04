"""Fake auth scenario builders for vertical API/CLI tests."""

from __future__ import annotations

import copy
from pathlib import Path

from pyicloud.adapters.auth import FakeScenarioAuthSessionAdapter
from pyicloud.adapters.session import InMemoryApiSessionStore
from pyicloud.adapters.store import FileSessionStoreAdapter
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.auth_session import AuthSessionService
from pyicloud.application.core_services import CoreServicesApi

SCENARIO_BY_USERNAME = {
    "success@example.com": "success",
    "requires2fa@example.com": "requires_2fa",
    "invalid@example.com": "invalid_credentials",
    "expired@example.com": "expired_session",
}


class _DeterministicCoreServices(CoreServicesApi):
    _DEVICE_FIXTURES = {
        "success@example.com": [
            {
                "id": "device-iphone-1",
                "name": "Inean iPhone",
                "deviceDisplayName": "iPhone 15 Pro",
                "deviceClass": "iPhone",
                "deviceModel": "iPhone15,3",
                "batteryLevel": 0.76,
                "batteryStatus": "Charging",
                "location": {
                    "latitude": 40.4168,
                    "longitude": -3.7038,
                    "positionType": "GPS",
                    "timeStamp": 1700000000000,
                },
            },
            {
                "id": "device-ipad-1",
                "name": "Inean iPad",
                "deviceDisplayName": "iPad Pro",
                "deviceClass": "iPad",
                "deviceModel": "iPad13,11",
                "batteryLevel": 0.33,
                "batteryStatus": "NotCharging",
                "location": {
                    "latitude": 41.3874,
                    "longitude": 2.1686,
                    "positionType": "GPS",
                    "timeStamp": 1700000001234,
                },
            },
        ]
    }
    _ACCOUNT_FAMILY_FIXTURES = {
        "success@example.com": [
            {
                "dsid": "1000000001",
                "firstName": "Inean",
                "lastName": "User",
                "fullName": "Inean User",
                "appleId": "success@example.com",
                "isAdult": True,
            },
            {
                "dsid": "1000000002",
                "firstName": "Family",
                "lastName": "Member",
                "fullName": "Family Member",
                "appleId": "family.member@example.com",
                "isAdult": True,
            },
        ]
    }
    _ACCOUNT_STORAGE_FIXTURES = {
        "success@example.com": {
            "usage": {
                "comp_storage_in_bytes": 1250000000,
                "used_storage_in_bytes": 187500000000,
                "used_storage_in_percent": 37.5,
                "available_storage_in_bytes": 312500000000,
                "available_storage_in_percent": 62.5,
                "total_storage_in_bytes": 500000000000,
                "commerce_storage_in_bytes": 0,
                "quota_over": False,
                "quota_tier_max": False,
                "quota_almost_full": False,
                "quota_paid": True,
            },
            "usages_by_media": {
                "photos": {
                    "key": "photos",
                    "label": "Photos",
                    "color": "#F4B400",
                    "usage_in_bytes": 92000000000,
                },
                "drive": {
                    "key": "drive",
                    "label": "iCloud Drive",
                    "color": "#4285F4",
                    "usage_in_bytes": 68000000000,
                },
            },
        }
    }
    _DRIVE_NODES_TEMPLATE: dict[str, dict[str, object]] = {
        "/": {"name": "/", "type": "folder"},
        "/Documents": {"name": "Documents", "type": "folder"},
        "/Documents/notes.txt": {"name": "notes.txt", "type": "file", "content": b"hello from notes"},
        "/Photos": {"name": "Photos", "type": "folder"},
    }

    def __init__(self):
        super().__init__(devices=self, accounts=self, drive=self)
        self._drive_nodes_by_user: dict[str, dict[str, dict[str, object]]] = {}

    def _device(self, *, username: str, device_id: str) -> dict:
        for device in self._DEVICE_FIXTURES.get(username, []):
            if str(device["id"]) == device_id:
                return copy.deepcopy(device)
        raise KeyError(f"Device not found: {device_id}")

    # Device
    def list_devices(self, *, username: str):
        return copy.deepcopy(self._DEVICE_FIXTURES.get(username, []))

    def device_location(self, *, username: str, device_id: str):
        return copy.deepcopy(self._device(username=username, device_id=device_id)["location"])

    def device_status(self, *, username: str, device_id: str):
        device = self._device(username=username, device_id=device_id)
        return {
            "id": device["id"],
            "name": device["name"],
            "deviceClass": device["deviceClass"],
            "batteryLevel": device["batteryLevel"],
            "batteryStatus": device["batteryStatus"],
        }

    def device_play_sound(self, *, username: str, device_id: str, subject: str):  # noqa: ARG002
        self._device(username=username, device_id=device_id)
        return None

    def device_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool):  # noqa: ARG002
        self._device(username=username, device_id=device_id)
        return None

    def device_lost_mode(self, *, username: str, device_id: str, number: str, text: str, newpasscode: str):  # noqa: ARG002
        self._device(username=username, device_id=device_id)
        return None

    # Account
    def account_devices(self, *, username: str):
        devices = self._DEVICE_FIXTURES.get(username, [])
        return [
            {
                "id": str(device["id"]),
                "name": str(device["name"]),
                "deviceDisplayName": str(device["deviceDisplayName"]),
                "deviceClass": str(device["deviceClass"]),
                "deviceModel": str(device["deviceModel"]),
            }
            for device in devices
        ]

    def account_family(self, *, username: str):
        return copy.deepcopy(self._ACCOUNT_FAMILY_FIXTURES.get(username, []))

    def account_storage(self, *, username: str):
        return copy.deepcopy(
            self._ACCOUNT_STORAGE_FIXTURES.get(username, {"usage": {}, "usages_by_media": {}})
        )

    # Drive
    @staticmethod
    def _normalize_path(path: str) -> str:
        clean = (path or "").strip()
        if not clean or clean == "/":
            return "/"
        if not clean.startswith("/"):
            clean = f"/{clean}"
        if len(clean) > 1 and clean.endswith("/"):
            clean = clean[:-1]
        return clean

    @classmethod
    def _parent_path(cls, path: str) -> str | None:
        clean = cls._normalize_path(path)
        if clean == "/":
            return None
        parent = clean.rsplit("/", 1)[0]
        return parent if parent else "/"

    @classmethod
    def _node_metadata(cls, path: str, node: dict[str, object]) -> dict[str, object]:
        size = 0
        if str(node.get("type")) == "file":
            content = node.get("content", b"")
            if isinstance(content, (bytes, bytearray)):
                size = len(content)
            else:
                size = len(bytes(str(content), encoding="utf-8"))
        return {
            "path": path,
            "name": str(node["name"]),
            "type": str(node.get("type", "file")),
            "size": size,
            "date_changed": None,
            "date_modified": None,
            "date_last_open": None,
        }

    def _drive_nodes(self, *, username: str) -> dict[str, dict[str, object]]:
        nodes = self._drive_nodes_by_user.get(username)
        if nodes is not None:
            return nodes
        nodes = {
            path: copy.deepcopy(node)
            for path, node in self._DRIVE_NODES_TEMPLATE.items()
        }
        self._drive_nodes_by_user[username] = nodes
        return nodes

    def _drive_node(self, *, username: str, path: str) -> tuple[str, dict[str, object]]:
        normalized_path = self._normalize_path(path)
        node = self._drive_nodes(username=username).get(normalized_path)
        if node is None:
            raise KeyError(f"Drive path not found: {normalized_path}")
        return normalized_path, node

    def _drive_children(self, *, username: str, path: str) -> list[dict[str, object]]:
        nodes = self._drive_nodes(username=username)
        parent = self._normalize_path(path)
        children: list[dict[str, object]] = []
        for child_path, node in nodes.items():
            if child_path == parent:
                continue
            if self._parent_path(child_path) != parent:
                continue
            children.append(self._node_metadata(child_path, node))
        return sorted(children, key=lambda item: str(item["name"]))

    def drive_tree(self, *, username: str, path: str):
        normalized_path, node = self._drive_node(username=username, path=path)
        data = self._node_metadata(normalized_path, node)
        data["children"] = self._drive_children(username=username, path=normalized_path)
        return data

    def drive_file_metadata(self, *, username: str, path: str):  # noqa: ARG002
        normalized_path, node = self._drive_node(username=username, path=path)
        return self._node_metadata(normalized_path, node)

    def drive_file_content(self, *, username: str, path: str):  # noqa: ARG002
        _, node = self._drive_node(username=username, path=path)
        if str(node.get("type")) != "file":
            raise KeyError("Drive path is not a file")
        content = node.get("content", b"")
        if isinstance(content, bytes):
            return content
        if isinstance(content, bytearray):
            return bytes(content)
        return bytes(str(content), encoding="utf-8")

    def drive_create_folder(self, *, username: str, parent_path: str, name: str):
        parent_normalized, parent = self._drive_node(username=username, path=parent_path)
        if str(parent.get("type")) != "folder":
            raise KeyError("Parent path is not a folder")
        child_name = name.strip()
        if not child_name:
            raise RuntimeError("Folder name cannot be empty")
        child_path = self._normalize_path(f"{parent_normalized}/{child_name}")
        nodes = self._drive_nodes(username=username)
        if child_path in nodes:
            raise RuntimeError(f"Drive path already exists: {child_path}")
        nodes[child_path] = {"name": child_name, "type": "folder"}
        return None

    def drive_upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes):
        parent_normalized, parent = self._drive_node(username=username, path=parent_path)
        if str(parent.get("type")) != "folder":
            raise KeyError("Parent path is not a folder")
        file_name = filename.strip()
        if not file_name:
            raise RuntimeError("File name cannot be empty")
        file_path = self._normalize_path(f"{parent_normalized}/{file_name}")
        nodes = self._drive_nodes(username=username)
        nodes[file_path] = {"name": file_name, "type": "file", "content": bytes(content)}
        return None

    def drive_rename_node(self, *, username: str, path: str, new_name: str):
        source_path, source_node = self._drive_node(username=username, path=path)
        if source_path == "/":
            raise RuntimeError("Cannot rename root node")
        parent = self._parent_path(source_path)
        assert parent is not None
        target_name = new_name.strip()
        if not target_name:
            raise RuntimeError("New name cannot be empty")
        target_path = self._normalize_path(f"{parent}/{target_name}")

        nodes = self._drive_nodes(username=username)
        if target_path in nodes:
            raise RuntimeError(f"Drive path already exists: {target_path}")

        affected_paths = [node_path for node_path in nodes if node_path == source_path or node_path.startswith(f"{source_path}/")]
        moved_nodes: dict[str, dict[str, object]] = {}
        for old_path in sorted(affected_paths, key=len):
            suffix = old_path[len(source_path) :]
            new_path = f"{target_path}{suffix}"
            node = copy.deepcopy(nodes[old_path])
            node["name"] = "/" if new_path == "/" else new_path.rsplit("/", 1)[-1]
            moved_nodes[new_path] = node

        for old_path in affected_paths:
            del nodes[old_path]
        nodes.update(moved_nodes)
        if source_node.get("type") == "file":
            nodes[target_path]["name"] = target_name
        return None

    def drive_delete_node(self, *, username: str, path: str):
        target_path, _ = self._drive_node(username=username, path=path)
        if target_path == "/":
            raise RuntimeError("Cannot delete root node")
        nodes = self._drive_nodes(username=username)
        to_delete = [node_path for node_path in nodes if node_path == target_path or node_path.startswith(f"{target_path}/")]
        for node_path in to_delete:
            del nodes[node_path]
        return None


def build_fake_auth_api_service(tmp_path: Path) -> AuthApiService:
    session_store = InMemoryApiSessionStore()
    signer = JwtTokenSigner(secret="test-secret-at-least-thirty-two-bytes")

    def auth_service_factory(username: str, password: str) -> AuthSessionService:  # noqa: ARG001
        scenario = SCENARIO_BY_USERNAME.get(username, "success")
        adapter = FakeScenarioAuthSessionAdapter(scenario=scenario)
        store = FileSessionStoreAdapter(root_dir=tmp_path / "sessions")
        return AuthSessionService(auth=adapter, store=store)

    return AuthApiService(
        token_signer=signer,
        session_query=session_store,
        session_command=session_store,
        auth_service_factory=auth_service_factory,
        token_ttl_seconds=3600,
        challenge_ttl_seconds=300,
    )


def build_noop_core_services() -> CoreServicesApi:
    return _DeterministicCoreServices()


def build_deterministic_core_services() -> CoreServicesApi:
    return _DeterministicCoreServices()
