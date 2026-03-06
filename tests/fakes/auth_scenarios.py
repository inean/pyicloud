"""Fake auth scenario builders for vertical API/CLI tests."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path

from pyicloud.adapters.auth import FakeScenarioAuthSessionAdapter
from pyicloud.adapters.session import InMemoryApiSessionStore
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.auth_session import AuthSessionService
from pyicloud.application.core_services import CoreServicesApi
from pyicloud.platform.storage import FileSessionStoreAdapter
from pyicloud.ports import AccessControlQueryPort

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
    _CALENDAR_FIXTURES = {
        "success@example.com": {
            "calendars": [
                {"guid": "cal-work-1", "title": "Work", "isDefault": True},
                {"guid": "cal-personal-1", "title": "Personal", "isDefault": False},
            ],
            "events": [
                {
                    "guid": "event-work-1",
                    "pguid": "cal-work-1",
                    "title": "Roadmap Review",
                    "location": "Madrid Office",
                    "startDate": "2026-03-05T09:00:00+01:00",
                    "endDate": "2026-03-05T10:00:00+01:00",
                },
                {
                    "guid": "event-personal-1",
                    "pguid": "cal-personal-1",
                    "title": "Gym",
                    "location": "Local Gym",
                    "startDate": "2026-03-06T18:00:00+01:00",
                    "endDate": "2026-03-06T19:00:00+01:00",
                },
            ],
            "details": {
                "cal-work-1:event-work-1": {
                    "guid": "event-work-1",
                    "pguid": "cal-work-1",
                    "title": "Roadmap Review",
                    "location": "Madrid Office",
                    "notes": "Discuss Q2 milestones",
                    "attendeeCount": 6,
                },
                "cal-personal-1:event-personal-1": {
                    "guid": "event-personal-1",
                    "pguid": "cal-personal-1",
                    "title": "Gym",
                    "location": "Local Gym",
                    "notes": "Leg day",
                    "attendeeCount": 1,
                },
            },
        }
    }
    _CONTACTS_FIXTURES = {
        "success@example.com": [
            {
                "firstName": "Inean",
                "lastName": "User",
                "displayName": "Inean User",
                "emails": [{"label": "work", "value": "success@example.com"}],
                "phones": [{"label": "mobile", "value": "+34600123456"}],
            },
            {
                "firstName": "Family",
                "lastName": "Member",
                "displayName": "Family Member",
                "emails": [{"label": "home", "value": "family.member@example.com"}],
                "phones": [{"label": "mobile", "value": "+34600987654"}],
            },
        ]
    }
    _REMINDER_LISTS_TEMPLATE = {
        "success@example.com": {
            "Personal": [
                {
                    "title": "Buy milk",
                    "desc": "2L whole",
                    "due": datetime(2026, 3, 5, 19, 0, tzinfo=UTC),
                }
            ],
            "Work": [
                {
                    "title": "Send status update",
                    "desc": "Weekly sync",
                    "due": datetime(2026, 3, 5, 16, 0, tzinfo=UTC),
                }
            ],
        }
    }
    _PHOTOS_FIXTURES = {
        "success@example.com": {
            "albums": [
                {"name": "All Photos", "count": 2},
                {"name": "Favorites", "count": 1},
            ],
            "assets_by_album": {
                "All Photos": [
                    {
                        "id": "photo-1",
                        "album": "All Photos",
                        "filename": "beach.jpg",
                        "size": 13,
                        "created": "2026-03-04T10:00:00+00:00",
                        "width": 2048,
                        "height": 1536,
                        "versions": {
                            "original": {
                                "filename": "beach.jpg",
                                "width": 2048,
                                "height": 1536,
                                "size": 13,
                                "type": "image/jpeg",
                            },
                            "thumb": {
                                "filename": "beach.jpg",
                                "width": 320,
                                "height": 240,
                                "size": 5,
                                "type": "image/jpeg",
                            },
                        },
                        "content_by_version": {"original": b"photo-1-bytes", "thumb": b"ph1-t"},
                    },
                    {
                        "id": "photo-2",
                        "album": "All Photos",
                        "filename": "sunset.jpg",
                        "size": 14,
                        "created": "2026-03-04T11:00:00+00:00",
                        "width": 1920,
                        "height": 1080,
                        "versions": {
                            "original": {
                                "filename": "sunset.jpg",
                                "width": 1920,
                                "height": 1080,
                                "size": 14,
                                "type": "image/jpeg",
                            },
                            "medium": {
                                "filename": "sunset.jpg",
                                "width": 1280,
                                "height": 720,
                                "size": 8,
                                "type": "image/jpeg",
                            },
                        },
                        "content_by_version": {"original": b"photo-2-bytes", "medium": b"ph2-medium"},
                    },
                ],
                "Favorites": [
                    {
                        "id": "photo-2",
                        "album": "Favorites",
                        "filename": "sunset.jpg",
                        "size": 14,
                        "created": "2026-03-04T11:00:00+00:00",
                        "width": 1920,
                        "height": 1080,
                        "versions": {
                            "original": {
                                "filename": "sunset.jpg",
                                "width": 1920,
                                "height": 1080,
                                "size": 14,
                                "type": "image/jpeg",
                            },
                        },
                        "content_by_version": {"original": b"photo-2-bytes"},
                    }
                ],
            },
        }
    }
    _UBIQUITY_NODES_TEMPLATE = {
        "/": {"item_id": 0, "name": "", "type": "folder", "size": None, "modified": None},
        "/Documents": {
            "item_id": 101,
            "name": "Documents",
            "type": "folder",
            "size": None,
            "modified": "2026-03-04T10:00:00+00:00",
        },
        "/Documents/shared.txt": {
            "item_id": 102,
            "name": "shared.txt",
            "type": "file",
            "size": 14,
            "modified": "2026-03-04T10:05:00+00:00",
            "content": b"shared-content",
        },
        "/Notes": {
            "item_id": 103,
            "name": "Notes",
            "type": "folder",
            "size": None,
            "modified": "2026-03-04T09:00:00+00:00",
        },
    }

    def __init__(self):
        super().__init__(
            devices=self,
            accounts=self,
            drive=self,
            calendars=self,
            contacts=self,
            reminders=self,
            photos=self,
            ubiquity=self,
        )
        self._drive_nodes_by_user: dict[str, dict[str, dict[str, object]]] = {}
        self._reminder_lists_by_user: dict[str, dict[str, list[dict[str, object]]]] = {}
        self._ubiquity_nodes_by_user: dict[str, dict[str, dict[str, object]]] = {}

    def _device(self, *, username: str, device_id: str) -> dict:
        for device in self._DEVICE_FIXTURES.get(username, []):
            if str(device["id"]) == device_id:
                return copy.deepcopy(device)
        raise KeyError(f"Device not found: {device_id}")

    # Device
    async def list_devices(self, *, username: str):
        return copy.deepcopy(self._DEVICE_FIXTURES.get(username, []))

    async def device_location(self, *, username: str, device_id: str):
        return copy.deepcopy(self._device(username=username, device_id=device_id)["location"])

    async def device_status(self, *, username: str, device_id: str):
        device = self._device(username=username, device_id=device_id)
        return {
            "id": device["id"],
            "name": device["name"],
            "deviceClass": device["deviceClass"],
            "batteryLevel": device["batteryLevel"],
            "batteryStatus": device["batteryStatus"],
        }

    async def device_play_sound(self, *, username: str, device_id: str, subject: str):  # noqa: ARG002
        self._device(username=username, device_id=device_id)
        return None

    async def device_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool):  # noqa: ARG002
        self._device(username=username, device_id=device_id)
        return None

    async def device_lost_mode(self, *, username: str, device_id: str, number: str, text: str, newpasscode: str):  # noqa: ARG002
        self._device(username=username, device_id=device_id)
        return None

    # Account
    async def account_devices(self, *, username: str):
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

    async def account_family(self, *, username: str):
        return copy.deepcopy(self._ACCOUNT_FAMILY_FIXTURES.get(username, []))

    async def account_storage(self, *, username: str):
        return copy.deepcopy(self._ACCOUNT_STORAGE_FIXTURES.get(username, {"usage": {}, "usages_by_media": {}}))

    # Calendar
    async def calendars(self, *, username: str):
        fixtures = self._CALENDAR_FIXTURES.get(username, {})
        return copy.deepcopy(fixtures.get("calendars", []))

    async def events(
        self,
        *,
        username: str,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ):
        fixtures = self._CALENDAR_FIXTURES.get(username, {})
        events = copy.deepcopy(fixtures.get("events", []))
        if from_dt is None and to_dt is None:
            return events

        filtered: list[dict[str, object]] = []
        for event in events:
            raw_start = str(event.get("startDate", ""))
            try:
                event_start = datetime.fromisoformat(raw_start)
            except ValueError:
                continue
            if from_dt is not None and event_start < from_dt:
                continue
            if to_dt is not None and event_start > to_dt:
                continue
            filtered.append(event)
        return filtered

    async def event_detail(self, *, username: str, calendar_guid: str, event_guid: str):
        fixtures = self._CALENDAR_FIXTURES.get(username, {})
        details = fixtures.get("details", {})
        key = f"{calendar_guid}:{event_guid}"
        if not isinstance(details, dict) or key not in details:
            raise KeyError(f"Calendar event not found: {key}")
        detail = details[key]
        assert isinstance(detail, dict)
        return copy.deepcopy(detail)

    # Contacts
    async def all_contacts(self, *, username: str):
        return copy.deepcopy(self._CONTACTS_FIXTURES.get(username, []))

    # Reminders
    def _reminder_lists(self, *, username: str) -> dict[str, list[dict[str, object]]]:
        existing = self._reminder_lists_by_user.get(username)
        if existing is not None:
            return existing
        lists = copy.deepcopy(self._REMINDER_LISTS_TEMPLATE.get(username, {}))
        self._reminder_lists_by_user[username] = lists
        return lists

    async def reminder_lists(self, *, username: str):
        return copy.deepcopy(self._reminder_lists(username=username))

    async def create_reminder(
        self,
        *,
        username: str,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        list_name = (collection or "Personal").strip() or "Personal"
        lists = self._reminder_lists(username=username)
        reminders = lists.setdefault(list_name, [])
        reminders.append({"title": title, "desc": description, "due": due_date})
        return True

    # Photos
    @staticmethod
    def _strip_photo_content(asset: dict[str, object]) -> dict[str, object]:
        clean = copy.deepcopy(asset)
        clean.pop("content_by_version", None)
        return clean

    def _photo_assets_by_album(self, *, username: str) -> dict[str, list[dict[str, object]]]:
        fixtures = self._PHOTOS_FIXTURES.get(username, {})
        data = fixtures.get("assets_by_album", {})
        if not isinstance(data, dict):
            return {}
        return copy.deepcopy(data)

    async def photos_albums(self, *, username: str):
        fixtures = self._PHOTOS_FIXTURES.get(username, {})
        albums = fixtures.get("albums", [])
        return copy.deepcopy(albums)

    async def photos_assets(
        self,
        *,
        username: str,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ):
        assets_by_album = self._photo_assets_by_album(username=username)
        if album not in assets_by_album:
            raise KeyError(f"Photo album not found: {album}")
        assets = assets_by_album[album][offset : offset + limit]
        return [self._strip_photo_content(asset) for asset in assets]

    async def photo_asset_metadata(self, *, username: str, asset_id: str, album: str = "All Photos"):
        assets = await self.photos_assets(username=username, album=album, limit=10000, offset=0)
        for asset in assets:
            if str(asset["id"]) == asset_id:
                return copy.deepcopy(asset)
        raise KeyError(f"Photo asset not found: {asset_id}")

    async def photo_asset_content(
        self,
        *,
        username: str,
        asset_id: str,
        album: str = "All Photos",
        version: str = "original",
    ):
        assets_by_album = self._photo_assets_by_album(username=username)
        if album not in assets_by_album:
            raise KeyError(f"Photo album not found: {album}")
        for asset in assets_by_album[album]:
            if str(asset["id"]) != asset_id:
                continue
            raw_content = asset.get("content_by_version", {})
            if not isinstance(raw_content, dict) or version not in raw_content:
                raise KeyError(f"Photo version not found: {version}")
            content = raw_content[version]
            if isinstance(content, bytes):
                return content
            if isinstance(content, bytearray):
                return bytes(content)
            return bytes(str(content), encoding="utf-8")
        raise KeyError(f"Photo asset not found: {asset_id}")

    # Ubiquity
    @classmethod
    def _normalize_ubiquity_path(cls, path: str) -> str:
        return cls._normalize_path(path)

    def _ubiquity_nodes(self, *, username: str) -> dict[str, dict[str, object]]:
        nodes = self._ubiquity_nodes_by_user.get(username)
        if nodes is not None:
            return nodes
        nodes = {path: copy.deepcopy(node) for path, node in self._UBIQUITY_NODES_TEMPLATE.items()}
        self._ubiquity_nodes_by_user[username] = nodes
        return nodes

    def _ubiquity_node(self, *, username: str, path: str) -> tuple[str, dict[str, object]]:
        normalized_path = self._normalize_ubiquity_path(path)
        node = self._ubiquity_nodes(username=username).get(normalized_path)
        if node is None:
            raise KeyError(f"Ubiquity path not found: {normalized_path}")
        return normalized_path, node

    @classmethod
    def _ubiquity_metadata(cls, path: str, node: dict[str, object]) -> dict[str, object]:
        return {
            "path": path,
            "item_id": node.get("item_id"),
            "name": str(node.get("name", "")),
            "type": str(node.get("type", "file")),
            "size": node.get("size"),
            "modified": node.get("modified"),
        }

    def _ubiquity_children(self, *, username: str, path: str) -> list[dict[str, object]]:
        nodes = self._ubiquity_nodes(username=username)
        parent = self._normalize_ubiquity_path(path)
        children: list[dict[str, object]] = []
        for child_path, node in nodes.items():
            if child_path == parent:
                continue
            if self._parent_path(child_path) != parent:
                continue
            children.append(self._ubiquity_metadata(child_path, node))
        return sorted(children, key=lambda item: str(item["name"]))

    async def ubiquity_tree(self, *, username: str, path: str):
        normalized_path, node = self._ubiquity_node(username=username, path=path)
        data = self._ubiquity_metadata(normalized_path, node)
        data["children"] = self._ubiquity_children(username=username, path=normalized_path)
        return data

    async def ubiquity_file_metadata(self, *, username: str, path: str):
        normalized_path, node = self._ubiquity_node(username=username, path=path)
        return self._ubiquity_metadata(normalized_path, node)

    async def ubiquity_file_content(self, *, username: str, path: str):
        _, node = self._ubiquity_node(username=username, path=path)
        if str(node.get("type")) != "file":
            raise KeyError("Ubiquity path is not a file")
        content = node.get("content", b"")
        if isinstance(content, bytes):
            return content
        if isinstance(content, bytearray):
            return bytes(content)
        return bytes(str(content), encoding="utf-8")

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
            if isinstance(content, bytes | bytearray):
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
        nodes = {path: copy.deepcopy(node) for path, node in self._DRIVE_NODES_TEMPLATE.items()}
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

    async def drive_tree(self, *, username: str, path: str):
        normalized_path, node = self._drive_node(username=username, path=path)
        data = self._node_metadata(normalized_path, node)
        data["children"] = self._drive_children(username=username, path=normalized_path)
        return data

    async def drive_file_metadata(self, *, username: str, path: str):  # noqa: ARG002
        normalized_path, node = self._drive_node(username=username, path=path)
        return self._node_metadata(normalized_path, node)

    async def drive_file_content(self, *, username: str, path: str):  # noqa: ARG002
        _, node = self._drive_node(username=username, path=path)
        if str(node.get("type")) != "file":
            raise KeyError("Drive path is not a file")
        content = node.get("content", b"")
        if isinstance(content, bytes):
            return content
        if isinstance(content, bytearray):
            return bytes(content)
        return bytes(str(content), encoding="utf-8")

    async def drive_create_folder(self, *, username: str, parent_path: str, name: str):
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

    async def drive_upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes):
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

    async def drive_rename_node(self, *, username: str, path: str, new_name: str):
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

        affected_paths = [
            node_path for node_path in nodes if node_path == source_path or node_path.startswith(f"{source_path}/")
        ]
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

    async def drive_delete_node(self, *, username: str, path: str):
        target_path, _ = self._drive_node(username=username, path=path)
        if target_path == "/":
            raise RuntimeError("Cannot delete root node")
        nodes = self._drive_nodes(username=username)
        to_delete = [
            node_path for node_path in nodes if node_path == target_path or node_path.startswith(f"{target_path}/")
        ]
        for node_path in to_delete:
            del nodes[node_path]
        return None


def build_fake_auth_api_service(
    tmp_path: Path,
    *,
    access_query: AccessControlQueryPort | None = None,
    enforce_allowlist: bool = False,
) -> AuthApiService:
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
        access_query=access_query,
        enforce_allowlist=enforce_allowlist,
        token_ttl_seconds=3600,
        challenge_ttl_seconds=300,
    )


def build_noop_core_services() -> CoreServicesApi:
    return _DeterministicCoreServices()


def build_deterministic_core_services() -> CoreServicesApi:
    return _DeterministicCoreServices()
