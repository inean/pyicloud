"""Application façade for device/account/drive API operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pyicloud.ports import AccountServicePort, DeviceServicePort, DriveServicePort


class CoreServicesApi:
    """Expose API-oriented operations over device/account/drive outbound ports."""

    def __init__(
        self,
        *,
        devices: DeviceServicePort,
        accounts: AccountServicePort,
        drive: DriveServicePort,
    ):
        self._devices = devices
        self._accounts = accounts
        self._drive = drive

    def list_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return self._devices.list_devices(username=username)

    def device_location(self, *, username: str, device_id: str) -> Mapping[str, Any]:
        return self._devices.location(username=username, device_id=device_id)

    def device_status(self, *, username: str, device_id: str) -> Mapping[str, Any]:
        return self._devices.status(username=username, device_id=device_id)

    def device_play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        self._devices.play_sound(username=username, device_id=device_id, subject=subject)

    def device_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        self._devices.display_message(
            username=username,
            device_id=device_id,
            subject=subject,
            message=message,
            sounds=sounds,
        )

    def device_lost_mode(
        self,
        *,
        username: str,
        device_id: str,
        number: str,
        text: str,
        newpasscode: str,
    ) -> None:
        self._devices.lost_mode(
            username=username,
            device_id=device_id,
            number=number,
            text=text,
            newpasscode=newpasscode,
        )

    def account_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return self._accounts.account_devices(username=username)

    def account_family(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return self._accounts.account_family(username=username)

    def account_storage(self, *, username: str) -> Mapping[str, Any]:
        return self._accounts.account_storage(username=username)

    def drive_tree(self, *, username: str, path: str) -> Mapping[str, Any]:
        return self._drive.tree(username=username, path=path)

    def drive_file_metadata(self, *, username: str, path: str) -> Mapping[str, Any]:
        return self._drive.file_metadata(username=username, path=path)

    def drive_file_content(self, *, username: str, path: str) -> bytes:
        return self._drive.file_content(username=username, path=path)

    def drive_create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        self._drive.create_folder(username=username, parent_path=parent_path, name=name)

    def drive_upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        self._drive.upload_file(username=username, parent_path=parent_path, filename=filename, content=content)

    def drive_rename_node(self, *, username: str, path: str, new_name: str) -> None:
        self._drive.rename_node(username=username, path=path, new_name=new_name)

    def drive_delete_node(self, *, username: str, path: str) -> None:
        self._drive.delete_node(username=username, path=path)
