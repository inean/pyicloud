"""Legacy-backed implementation of core service ports for API migration."""

from __future__ import annotations

import io
from collections.abc import Mapping, Sequence
from typing import Any

from pyicloud.bootstrap import build_service_endpoint_restore
from pyicloud.ports import AccountServicePort, DeviceServicePort, DriveServicePort
from pyicloud.services import PyiCloudServices


class _NamedBytesIO(io.BytesIO):
    def __init__(self, data: bytes, name: str):
        super().__init__(data)
        self.name = name


class LegacyCoreServicesAdapter(DeviceServicePort, AccountServicePort, DriveServicePort):
    """Use existing service classes as adapters behind new API-facing ports."""

    def __init__(self, *, endpoint_restore_factory=build_service_endpoint_restore):
        self._restore = endpoint_restore_factory()

    def _services(self, *, username: str) -> PyiCloudServices:
        endpoint = self._restore.restore(account_id=username, password="")
        if endpoint is None:
            raise RuntimeError(f"No stored endpoint payload found for account: {username}")
        return PyiCloudServices(endpoint=endpoint)

    @staticmethod
    def _iter_devices(manager: Any) -> list[Any]:
        try:
            keys = list(manager.keys())
            return [manager[key] for key in keys]
        except Exception:  # noqa: BLE001
            pass

        # Fallback for index-based manager implementation.
        devices = []
        idx = 0
        while True:
            try:
                devices.append(manager[idx])
                idx += 1
            except Exception:  # noqa: BLE001
                break
        return devices

    def _get_device(self, *, username: str, device_id: str) -> Any:
        manager = self._services(username=username).devices
        for device in self._iter_devices(manager):
            if str(device["id"]) == device_id:
                return device
        raise KeyError(f"Device not found: {device_id}")

    def list_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        manager = self._services(username=username).devices
        return [dict(device.data) for device in self._iter_devices(manager)]

    def location(self, *, username: str, device_id: str) -> Mapping[str, Any]:
        device = self._get_device(username=username, device_id=device_id)
        location = device.location()
        if isinstance(location, dict):
            return location
        return {"location": location}

    def status(self, *, username: str, device_id: str) -> Mapping[str, Any]:
        return dict(self._get_device(username=username, device_id=device_id).status())

    def play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        self._get_device(username=username, device_id=device_id).play_sound(subject=subject)

    def display_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        self._get_device(username=username, device_id=device_id).display_message(
            subject=subject,
            message=message,
            sounds=sounds,
        )

    def lost_mode(
        self,
        *,
        username: str,
        device_id: str,
        number: str,
        text: str,
        newpasscode: str,
    ) -> None:
        self._get_device(username=username, device_id=device_id).lost_device(
            number=number,
            text=text,
            newpasscode=newpasscode,
        )

    def account_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return [dict(item) for item in self._services(username=username).account.devices]

    def account_family(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        family = self._services(username=username).account.family
        return [dict(getattr(member, "_attrs", {})) for member in family]

    def account_storage(self, *, username: str) -> Mapping[str, Any]:
        storage = self._services(username=username).account.storage
        usage = storage.usage
        return {
            "usage": {
                "comp_storage_in_bytes": usage.comp_storage_in_bytes,
                "used_storage_in_bytes": usage.used_storage_in_bytes,
                "used_storage_in_percent": usage.used_storage_in_percent,
                "available_storage_in_bytes": usage.available_storage_in_bytes,
                "available_storage_in_percent": usage.available_storage_in_percent,
                "total_storage_in_bytes": usage.total_storage_in_bytes,
                "commerce_storage_in_bytes": usage.commerce_storage_in_bytes,
                "quota_over": usage.quota_over,
                "quota_tier_max": usage.quota_tier_max,
                "quota_almost_full": usage.quota_almost_full,
                "quota_paid": usage.quota_paid,
            },
            "usages_by_media": {
                key: {
                    "key": media.key,
                    "label": media.label,
                    "color": media.color,
                    "usage_in_bytes": media.usage_in_bytes,
                }
                for key, media in storage.usages_by_media.items()
            },
        }

    def _resolve_drive_node(self, *, username: str, path: str):
        node = self._services(username=username).drive
        clean_path = path.strip()
        if not clean_path or clean_path == "/":
            return node
        for part in [segment for segment in clean_path.strip("/").split("/") if segment]:
            node = node[part]
        return node

    @staticmethod
    def _node_metadata(path: str, node: Any) -> dict[str, Any]:
        return {
            "path": path or "/",
            "name": node.name,
            "type": node.type,
            "size": node.size,
            "date_changed": str(node.date_changed) if getattr(node, "date_changed", None) else None,
            "date_modified": str(node.date_modified) if getattr(node, "date_modified", None) else None,
            "date_last_open": str(node.date_last_open) if getattr(node, "date_last_open", None) else None,
        }

    def tree(self, *, username: str, path: str) -> Mapping[str, Any]:
        node = self._resolve_drive_node(username=username, path=path)
        data = self._node_metadata(path=path or "/", node=node)
        data["children"] = node.dir()
        return data

    def file_metadata(self, *, username: str, path: str) -> Mapping[str, Any]:
        return self._node_metadata(path=path, node=self._resolve_drive_node(username=username, path=path))

    def file_content(self, *, username: str, path: str) -> bytes:
        node = self._resolve_drive_node(username=username, path=path)
        chunks: list[bytes] = []
        with node.open(stream=True) as response:
            for chunk in response.iter_raw():
                if isinstance(chunk, bytes):
                    chunks.append(chunk)
                else:
                    chunks.append(bytes(chunk))
        return b"".join(chunks)

    def create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        parent = self._resolve_drive_node(username=username, path=parent_path)
        parent.mkdir(name)

    def upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        parent = self._resolve_drive_node(username=username, path=parent_path)
        fileobj = _NamedBytesIO(content, name=filename)
        parent.upload(fileobj)

    def rename_node(self, *, username: str, path: str, new_name: str) -> None:
        self._resolve_drive_node(username=username, path=path).rename(new_name)

    def delete_node(self, *, username: str, path: str) -> None:
        self._resolve_drive_node(username=username, path=path).delete()
