"""Compatibility facade delegating service operations to context-scoped application services."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from pyicloud.contexts.services.account.application import AccountApplicationService
from pyicloud.contexts.services.calendar.application import CalendarApplicationService
from pyicloud.contexts.services.contacts.application import ContactsApplicationService
from pyicloud.contexts.services.contracts.services import (
    AccountServicePort,
    CalendarServicePort,
    ContactsServicePort,
    DeviceServicePort,
    DriveServicePort,
    PhotosServicePort,
    RemindersServicePort,
    UbiquityServicePort,
)
from pyicloud.contexts.services.devices.application import DevicesApplicationService
from pyicloud.contexts.services.drive.application import DriveApplicationService
from pyicloud.contexts.services.photos.application import PhotosApplicationService
from pyicloud.contexts.services.reminders.application import RemindersApplicationService
from pyicloud.contexts.services.ubiquity.application import UbiquityApplicationService
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


class CoreServicesApi:
    """Compatibility facade preserving the legacy API while using context services."""

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
        self._devices = DevicesApplicationService(port=devices)
        self._account = AccountApplicationService(port=accounts)
        self._drive = DriveApplicationService(port=drive)
        self._calendar = CalendarApplicationService(port=calendars)
        self._contacts = ContactsApplicationService(port=contacts)
        self._reminders = RemindersApplicationService(port=reminders)
        self._photos = PhotosApplicationService(port=photos)
        self._ubiquity = UbiquityApplicationService(port=ubiquity)

    async def list_devices(self, *, username: str) -> Sequence[DeviceRecordDTO]:
        return await self._devices.list_devices(username=username)

    async def device_location(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        return await self._devices.location(username=username, device_id=device_id)

    async def device_status(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        return await self._devices.status(username=username, device_id=device_id)

    async def device_play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        await self._devices.play_sound(username=username, device_id=device_id, subject=subject)

    async def device_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        await self._devices.message(
            username=username,
            device_id=device_id,
            subject=subject,
            message=message,
            sounds=sounds,
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
        await self._devices.lost_mode(
            username=username,
            device_id=device_id,
            number=number,
            text=text,
            newpasscode=newpasscode,
        )

    async def account_devices(self, *, username: str) -> Sequence[AccountDeviceDTO]:
        return await self._account.account_devices(username=username)

    async def account_family(self, *, username: str) -> Sequence[AccountFamilyMemberDTO]:
        return await self._account.account_family(username=username)

    async def account_storage(self, *, username: str) -> AccountStorageDTO:
        return await self._account.account_storage(username=username)

    async def drive_tree(self, *, username: str, path: str) -> DriveNodeDTO:
        return await self._drive.tree(username=username, path=path)

    async def drive_file_metadata(self, *, username: str, path: str) -> DriveNodeDTO:
        return await self._drive.file_metadata(username=username, path=path)

    async def drive_file_content(self, *, username: str, path: str) -> bytes:
        return await self._drive.file_content(username=username, path=path)

    async def drive_create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        await self._drive.create_folder(username=username, parent_path=parent_path, name=name)

    async def drive_upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        await self._drive.upload_file(
            username=username,
            parent_path=parent_path,
            filename=filename,
            content=content,
        )

    async def drive_rename_node(self, *, username: str, path: str, new_name: str) -> None:
        await self._drive.rename_node(username=username, path=path, new_name=new_name)

    async def drive_delete_node(self, *, username: str, path: str) -> None:
        await self._drive.delete_node(username=username, path=path)

    async def calendar_calendars(self, *, username: str) -> Sequence[CalendarDTO]:
        return await self._calendar.calendars(username=username)

    async def calendar_events(
        self,
        *,
        username: str,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> Sequence[CalendarEventDTO]:
        return await self._calendar.events(username=username, from_dt=from_dt, to_dt=to_dt)

    async def calendar_event_detail(
        self, *, username: str, calendar_guid: str, event_guid: str
    ) -> CalendarEventDetailDTO:
        return await self._calendar.event_detail(
            username=username,
            calendar_guid=calendar_guid,
            event_guid=event_guid,
        )

    async def contacts_all(self, *, username: str) -> Sequence[ContactDTO]:
        return await self._contacts.all_contacts(username=username)

    async def reminders_lists(self, *, username: str) -> ReminderListsDTO:
        return await self._reminders.reminder_lists(username=username)

    async def reminders_create(
        self,
        *,
        username: str,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return await self._reminders.create_reminder(
            username=username,
            title=title,
            description=description,
            collection=collection,
            due_date=due_date,
        )

    async def photos_albums(self, *, username: str) -> Sequence[PhotoAlbumDTO]:
        return await self._photos.list_albums(username=username)

    async def photos_assets(
        self,
        *,
        username: str,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[PhotoAssetDTO]:
        return await self._photos.list_assets(username=username, album=album, limit=limit, offset=offset)

    async def photo_asset_metadata(self, *, username: str, asset_id: str, album: str = "All Photos") -> PhotoAssetDTO:
        return await self._photos.asset_metadata(username=username, asset_id=asset_id, album=album)

    async def photo_asset_content(
        self,
        *,
        username: str,
        asset_id: str,
        album: str = "All Photos",
        version: str = "original",
    ) -> bytes:
        return await self._photos.asset_content(
            username=username,
            asset_id=asset_id,
            album=album,
            version=version,
        )

    async def ubiquity_tree(self, *, username: str, path: str) -> UbiquityNodeDTO:
        return await self._ubiquity.ubiquity_tree(username=username, path=path)

    async def ubiquity_file_metadata(self, *, username: str, path: str) -> UbiquityNodeDTO:
        return await self._ubiquity.ubiquity_file_metadata(username=username, path=path)

    async def ubiquity_file_content(self, *, username: str, path: str) -> bytes:
        return await self._ubiquity.ubiquity_file_content(username=username, path=path)


__all__ = ["CoreServicesApi"]
