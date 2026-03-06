"""Application façade for API-facing service operations."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from pyicloud.domain import (
    AccountDeviceDTO,
    AccountFamilyMemberDTO,
    AccountStorageDTO,
    DeviceRecordDTO,
    DriveNodeDTO,
)
from pyicloud.ports import (
    AccountServicePort,
    CalendarServicePort,
    ContactsServicePort,
    DeviceServicePort,
    DriveServicePort,
    PhotosServicePort,
    RemindersServicePort,
    UbiquityServicePort,
)
from pyicloud.upstream import bind_upstream_context


class CoreServicesApi:
    """Expose API-oriented operations over core outbound service ports."""

    def __init__(
        self,
        *,
        devices: DeviceServicePort,
        accounts: AccountServicePort,
        drive: DriveServicePort,
        calendars: CalendarServicePort,
        contacts: ContactsServicePort,
        reminders: RemindersServicePort,
        photos: PhotosServicePort,
        ubiquity: UbiquityServicePort,
    ):
        self._devices = devices
        self._accounts = accounts
        self._drive = drive
        self._calendars = calendars
        self._contacts = contacts
        self._reminders = reminders
        self._photos = photos
        self._ubiquity = ubiquity

    @staticmethod
    async def _run_with_operation[T](
        *,
        username: str,
        operation: str,
        call: Callable[[], Awaitable[T]],
    ) -> T:
        step = "find_devices" if operation == "devices.list" else operation.split(".")[-1]
        with bind_upstream_context(username=username, operation=operation, step=step):
            return await call()

    async def list_devices(self, *, username: str) -> Sequence[DeviceRecordDTO]:
        return await self._run_with_operation(
            username=username,
            operation="devices.list",
            call=lambda: self._devices.list_devices(username=username),
        )

    async def device_location(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        return await self._run_with_operation(
            username=username,
            operation="devices.location",
            call=lambda: self._devices.location(username=username, device_id=device_id),
        )

    async def device_status(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        return await self._run_with_operation(
            username=username,
            operation="devices.status",
            call=lambda: self._devices.status(username=username, device_id=device_id),
        )

    async def device_play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        await self._run_with_operation(
            username=username,
            operation="devices.play_sound",
            call=lambda: self._devices.play_sound(username=username, device_id=device_id, subject=subject),
        )

    async def device_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        await self._run_with_operation(
            username=username,
            operation="devices.message",
            call=lambda: self._devices.display_message(
                username=username,
                device_id=device_id,
                subject=subject,
                message=message,
                sounds=sounds,
            ),
        )

    async def device_lost_mode(
        self,
        *,
        username: str,
        device_id: str,
        number: str,
        text: str,
        newpasscode: str,
    ) -> None:
        await self._run_with_operation(
            username=username,
            operation="devices.lost_mode",
            call=lambda: self._devices.lost_mode(
                username=username,
                device_id=device_id,
                number=number,
                text=text,
                newpasscode=newpasscode,
            ),
        )

    async def account_devices(self, *, username: str) -> Sequence[AccountDeviceDTO]:
        return await self._run_with_operation(
            username=username,
            operation="account.devices",
            call=lambda: self._accounts.account_devices(username=username),
        )

    async def account_family(self, *, username: str) -> Sequence[AccountFamilyMemberDTO]:
        return await self._run_with_operation(
            username=username,
            operation="account.family",
            call=lambda: self._accounts.account_family(username=username),
        )

    async def account_storage(self, *, username: str) -> AccountStorageDTO:
        return await self._run_with_operation(
            username=username,
            operation="account.storage",
            call=lambda: self._accounts.account_storage(username=username),
        )

    async def drive_tree(self, *, username: str, path: str) -> DriveNodeDTO:
        return await self._run_with_operation(
            username=username,
            operation="drive.tree",
            call=lambda: self._drive.tree(username=username, path=path),
        )

    async def drive_file_metadata(self, *, username: str, path: str) -> DriveNodeDTO:
        return await self._run_with_operation(
            username=username,
            operation="drive.file_metadata",
            call=lambda: self._drive.file_metadata(username=username, path=path),
        )

    async def drive_file_content(self, *, username: str, path: str) -> bytes:
        return await self._run_with_operation(
            username=username,
            operation="drive.file_content",
            call=lambda: self._drive.file_content(username=username, path=path),
        )

    async def drive_create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        await self._run_with_operation(
            username=username,
            operation="drive.create_folder",
            call=lambda: self._drive.create_folder(username=username, parent_path=parent_path, name=name),
        )

    async def drive_upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        await self._run_with_operation(
            username=username,
            operation="drive.upload_file",
            call=lambda: self._drive.upload_file(
                username=username,
                parent_path=parent_path,
                filename=filename,
                content=content,
            ),
        )

    async def drive_rename_node(self, *, username: str, path: str, new_name: str) -> None:
        await self._run_with_operation(
            username=username,
            operation="drive.rename_node",
            call=lambda: self._drive.rename_node(username=username, path=path, new_name=new_name),
        )

    async def drive_delete_node(self, *, username: str, path: str) -> None:
        await self._run_with_operation(
            username=username,
            operation="drive.delete_node",
            call=lambda: self._drive.delete_node(username=username, path=path),
        )

    async def calendar_calendars(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return await self._run_with_operation(
            username=username,
            operation="calendar.calendars",
            call=lambda: self._calendars.calendars(username=username),
        )

    async def calendar_events(
        self,
        *,
        username: str,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> Sequence[Mapping[str, Any]]:
        return await self._run_with_operation(
            username=username,
            operation="calendar.events",
            call=lambda: self._calendars.events(username=username, from_dt=from_dt, to_dt=to_dt),
        )

    async def calendar_event_detail(self, *, username: str, calendar_guid: str, event_guid: str) -> Mapping[str, Any]:
        return await self._run_with_operation(
            username=username,
            operation="calendar.event_detail",
            call=lambda: self._calendars.event_detail(
                username=username,
                calendar_guid=calendar_guid,
                event_guid=event_guid,
            ),
        )

    async def contacts_all(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return await self._run_with_operation(
            username=username,
            operation="contacts.all",
            call=lambda: self._contacts.all_contacts(username=username),
        )

    async def reminders_lists(self, *, username: str) -> Mapping[str, Sequence[Mapping[str, Any]]]:
        return await self._run_with_operation(
            username=username,
            operation="reminders.lists",
            call=lambda: self._reminders.reminder_lists(username=username),
        )

    async def reminders_create(
        self,
        *,
        username: str,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return await self._run_with_operation(
            username=username,
            operation="reminders.create",
            call=lambda: self._reminders.create_reminder(
                username=username,
                title=title,
                description=description,
                collection=collection,
                due_date=due_date,
            ),
        )

    async def photos_albums(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return await self._run_with_operation(
            username=username,
            operation="photos.albums",
            call=lambda: self._photos.list_albums(username=username),
        )

    async def photos_assets(
        self,
        *,
        username: str,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Mapping[str, Any]]:
        return await self._run_with_operation(
            username=username,
            operation="photos.assets",
            call=lambda: self._photos.list_assets(username=username, album=album, limit=limit, offset=offset),
        )

    async def photo_asset_metadata(
        self, *, username: str, asset_id: str, album: str = "All Photos"
    ) -> Mapping[str, Any]:
        return await self._run_with_operation(
            username=username,
            operation="photos.asset_metadata",
            call=lambda: self._photos.asset_metadata(username=username, asset_id=asset_id, album=album),
        )

    async def photo_asset_content(
        self,
        *,
        username: str,
        asset_id: str,
        album: str = "All Photos",
        version: str = "original",
    ) -> bytes:
        return await self._run_with_operation(
            username=username,
            operation="photos.asset_content",
            call=lambda: self._photos.asset_content(
                username=username,
                asset_id=asset_id,
                album=album,
                version=version,
            ),
        )

    async def ubiquity_tree(self, *, username: str, path: str) -> Mapping[str, Any]:
        return await self._run_with_operation(
            username=username,
            operation="ubiquity.tree",
            call=lambda: self._ubiquity.ubiquity_tree(username=username, path=path),
        )

    async def ubiquity_file_metadata(self, *, username: str, path: str) -> Mapping[str, Any]:
        return await self._run_with_operation(
            username=username,
            operation="ubiquity.file_metadata",
            call=lambda: self._ubiquity.ubiquity_file_metadata(username=username, path=path),
        )

    async def ubiquity_file_content(self, *, username: str, path: str) -> bytes:
        return await self._run_with_operation(
            username=username,
            operation="ubiquity.file_content",
            call=lambda: self._ubiquity.ubiquity_file_content(username=username, path=path),
        )
