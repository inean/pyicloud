"""Compatibility service facade for legacy `PyiCloudService` imports."""

from __future__ import annotations

import asyncio
import warnings
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from pyicloud.adapters.auth import authenticate_legacy_endpoint
from pyicloud.adapters.service_endpoint import LegacyServiceEndpointFactoryAdapter
from pyicloud.adapters.services import LegacyCoreAdapterBundle, build_legacy_core_adapter_bundle
from pyicloud.adapters.store import FileSessionStoreAdapter
from pyicloud.ports import ServiceEndpointPort, SessionStorePort
from pyicloud.upstream import bind_upstream_context

COMPATIBILITY_POLICY: dict[str, tuple[str, ...]] = {
    "supported": (
        "Import surface: `from pyicloud import PyiCloudService`.",
        "Construction and auth bootstrap: `PyiCloudService(username, password='', interactive=None)`.",
        "Device compatibility surface: `api.devices`, `api.iphone`, and device action methods.",
        "Domain helper methods: `account_*`, `drive_*`, `calendar_*`, `contacts_all`, `reminders_*`, "
        "`photos_*`, `ubiquity_*`.",
        "Policy introspection: `PyiCloudService.compatibility_policy()`.",
    ),
    "deprecated": (
        "Legacy domain attributes (`account`, `drive`, `files`, `photos`, `calendar`, `contacts`, `reminders`).",
        "Legacy-style service-object semantics on those attributes are preserved only as thin adapters.",
    ),
    "removed": (
        "Direct passthrough to `pyicloud.services.PyiCloudServices` internals.",
        "Undocumented dynamic attributes from the historical monolithic service object.",
    ),
}


def _ensure_not_running_loop() -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop in this thread.
        return
    raise RuntimeError(
        "PyiCloudService cannot be instantiated inside a running event loop. "
        "Use API/CLI services from asynchronous contexts."
    )


class _CompatDevice:
    def __init__(self, *, api: PyiCloudService, payload: Mapping[str, Any]):
        self._api = api
        self._payload = dict(payload)
        self._device_id = str(self._payload.get("id", ""))
        if not self._device_id:
            raise KeyError("Device has no id")

    @property
    def data(self) -> Mapping[str, Any]:
        return dict(self._payload)

    def location(self) -> Mapping[str, Any]:
        return self._api.device_location(device_id=self._device_id)

    def status(self) -> Mapping[str, Any]:
        return self._api.device_status(device_id=self._device_id)

    def play_sound(self, subject: str = "Find my iPhone Alert") -> None:
        self._api.device_play_sound(device_id=self._device_id, subject=subject)

    def display_message(self, *, subject: str, message: str, sounds: bool = False) -> None:
        self._api.device_message(
            device_id=self._device_id,
            subject=subject,
            message=message,
            sounds=sounds,
        )

    def lost_device(self, *, number: str, text: str, newpasscode: str) -> None:
        self._api.device_lost_mode(
            device_id=self._device_id,
            number=number,
            text=text,
            newpasscode=newpasscode,
        )

    def __getitem__(self, key: str) -> Any:
        return self._payload[key]

    def __getattr__(self, name: str) -> Any:
        if name in self._payload:
            return self._payload[name]
        raise AttributeError(name)


class _CompatDevicesManager:
    def __init__(self, *, api: PyiCloudService):
        self._api = api

    def _payloads(self) -> list[Mapping[str, Any]]:
        return list(self._api.list_devices())

    def keys(self) -> list[str]:
        return [str(item.get("id")) for item in self._payloads() if item.get("id") is not None]

    def __iter__(self):
        for payload in self._payloads():
            yield _CompatDevice(api=self._api, payload=payload)

    def __len__(self) -> int:
        return len(self._payloads())

    def __getitem__(self, key: int | str) -> _CompatDevice:
        payloads = self._payloads()
        if isinstance(key, int):
            return _CompatDevice(api=self._api, payload=payloads[key])

        requested_id = str(key)
        for payload in payloads:
            if str(payload.get("id", "")) == requested_id:
                return _CompatDevice(api=self._api, payload=payload)
        raise KeyError(f"Device not found: {requested_id}")


class _CompatAccountFacade:
    def __init__(self, *, api: PyiCloudService):
        self._api = api

    @property
    def devices(self) -> Sequence[Mapping[str, Any]]:
        return self._api.account_devices()

    @property
    def family(self) -> Sequence[Mapping[str, Any]]:
        return self._api.account_family()

    @property
    def storage(self) -> Mapping[str, Any]:
        return self._api.account_storage()


class _CompatDriveFacade:
    def __init__(self, *, api: PyiCloudService):
        self._api = api

    def tree(self, *, path: str = "/") -> Mapping[str, Any]:
        return self._api.drive_tree(path=path)

    def file(self, *, path: str) -> Mapping[str, Any]:
        return self._api.drive_file_metadata(path=path)

    def download(self, *, path: str) -> bytes:
        return self._api.drive_file_content(path=path)

    def mkdir(self, *, parent_path: str, name: str) -> None:
        self._api.drive_create_folder(parent_path=parent_path, name=name)

    def upload(self, *, parent_path: str, filename: str, content: bytes) -> None:
        self._api.drive_upload_file(parent_path=parent_path, filename=filename, content=content)

    def rename(self, *, path: str, new_name: str) -> None:
        self._api.drive_rename_node(path=path, new_name=new_name)

    def delete(self, *, path: str) -> None:
        self._api.drive_delete_node(path=path)


class _CompatCalendarFacade:
    def __init__(self, *, api: PyiCloudService):
        self._api = api

    def calendars(self) -> Sequence[Mapping[str, Any]]:
        return self._api.calendar_calendars()

    def events(
        self,
        *,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> Sequence[Mapping[str, Any]]:
        return self._api.calendar_events(from_dt=from_dt, to_dt=to_dt)

    def get_event_detail(self, *, pguid: str, guid: str) -> Mapping[str, Any]:
        return self._api.calendar_event_detail(calendar_guid=pguid, event_guid=guid)


class _CompatContactsFacade:
    def __init__(self, *, api: PyiCloudService):
        self._api = api

    def all(self) -> Sequence[Mapping[str, Any]]:
        return self._api.contacts_all()


class _CompatRemindersFacade:
    def __init__(self, *, api: PyiCloudService):
        self._api = api

    @property
    def lists(self) -> Mapping[str, Sequence[Mapping[str, Any]]]:
        return self._api.reminders_lists()

    def post(
        self,
        *,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return self._api.reminders_create(
            title=title,
            description=description,
            collection=collection,
            due_date=due_date,
        )


class _CompatPhotosFacade:
    def __init__(self, *, api: PyiCloudService):
        self._api = api

    @property
    def albums(self) -> Sequence[Mapping[str, Any]]:
        return self._api.photos_albums()

    def assets(
        self,
        *,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Mapping[str, Any]]:
        return self._api.photos_assets(album=album, limit=limit, offset=offset)

    def asset(self, *, asset_id: str, album: str = "All Photos") -> Mapping[str, Any]:
        return self._api.photo_asset_metadata(asset_id=asset_id, album=album)

    def download(
        self,
        *,
        asset_id: str,
        album: str = "All Photos",
        version: str = "original",
    ) -> bytes:
        return self._api.photo_asset_content(asset_id=asset_id, album=album, version=version)


class _CompatUbiquityFacade:
    def __init__(self, *, api: PyiCloudService):
        self._api = api

    def tree(self, *, path: str = "/") -> Mapping[str, Any]:
        return self._api.ubiquity_tree(path=path)

    def file(self, *, path: str) -> Mapping[str, Any]:
        return self._api.ubiquity_file_metadata(path=path)

    def download(self, *, path: str) -> bytes:
        return self._api.ubiquity_file_content(path=path)


class PyiCloudService:
    """Compatibility facade wired through adapter composition (not direct legacy internals)."""

    def __init__(
        self,
        username: str,
        password: str = "",
        *,
        interactive: bool | None = None,
        _auth_runner: Any | None = None,
        _restore_builder: Any | None = None,
        _session_store: SessionStorePort | None = None,
        _endpoint_factory: ServiceEndpointPort | None = None,
    ):
        warnings.warn(
            "PyiCloudService compatibility facade is deprecated; migrate to pyicloud API/CLI services.",
            DeprecationWarning,
            stacklevel=2,
        )
        if interactive is None:
            interactive = password == ""

        _ensure_not_running_loop()
        session_store = _session_store or FileSessionStoreAdapter()
        endpoint_factory = _endpoint_factory or LegacyServiceEndpointFactoryAdapter()

        asyncio.run(
            authenticate_legacy_endpoint(
                username=username,
                password=password,
                interactive=interactive,
                auth_runner=_auth_runner,
                restore_builder=_restore_builder,
                store=session_store,
                endpoint_factory=endpoint_factory,
            )
        )

        self._username = username
        self._bundle: LegacyCoreAdapterBundle = build_legacy_core_adapter_bundle(
            session_store=session_store,
            endpoint_factory=endpoint_factory,
        )

    @classmethod
    def compatibility_policy(cls) -> Mapping[str, Sequence[str]]:
        """Return the explicit compatibility policy for this facade."""
        return {key: tuple(values) for key, values in COMPATIBILITY_POLICY.items()}

    @property
    def devices(self) -> _CompatDevicesManager:
        return _CompatDevicesManager(api=self)

    @property
    def iphone(self) -> _CompatDevice:
        if len(self.devices) == 0:
            raise RuntimeError(f"No devices available for account: {self._username}")
        return self.devices[0]

    def _warn_deprecated_surface(self, *, surface: str, replacement: str) -> None:
        warnings.warn(
            f"PyiCloudService surface `{surface}` is deprecated. {replacement}",
            DeprecationWarning,
            stacklevel=2,
        )

    def _run_with_operation[T](self, *, operation: str, call: Callable[[], T]) -> T:
        step = "find_devices" if operation == "devices.list" else operation.split(".")[-1]
        with bind_upstream_context(username=self._username, operation=operation, step=step):
            return call()

    @property
    def account(self) -> _CompatAccountFacade:
        self._warn_deprecated_surface(surface="account", replacement="Use account_* helper methods.")
        return _CompatAccountFacade(api=self)

    @property
    def drive(self) -> _CompatDriveFacade:
        self._warn_deprecated_surface(surface="drive", replacement="Use drive_* helper methods.")
        return _CompatDriveFacade(api=self)

    @property
    def files(self) -> _CompatUbiquityFacade:
        self._warn_deprecated_surface(surface="files", replacement="Use ubiquity_* helper methods.")
        return _CompatUbiquityFacade(api=self)

    @property
    def photos(self) -> _CompatPhotosFacade:
        self._warn_deprecated_surface(surface="photos", replacement="Use photos_* helper methods.")
        return _CompatPhotosFacade(api=self)

    @property
    def calendar(self) -> _CompatCalendarFacade:
        self._warn_deprecated_surface(surface="calendar", replacement="Use calendar_* helper methods.")
        return _CompatCalendarFacade(api=self)

    @property
    def contacts(self) -> _CompatContactsFacade:
        self._warn_deprecated_surface(surface="contacts", replacement="Use contacts_all() helper.")
        return _CompatContactsFacade(api=self)

    @property
    def reminders(self) -> _CompatRemindersFacade:
        self._warn_deprecated_surface(surface="reminders", replacement="Use reminders_* helper methods.")
        return _CompatRemindersFacade(api=self)

    def list_devices(self) -> Sequence[Mapping[str, Any]]:
        return self._run_with_operation(
            operation="devices.list",
            call=lambda: self._bundle.devices.list_devices(username=self._username),
        )

    def device_location(self, *, device_id: str) -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="devices.location",
            call=lambda: self._bundle.devices.location(username=self._username, device_id=device_id),
        )

    def device_status(self, *, device_id: str) -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="devices.status",
            call=lambda: self._bundle.devices.status(username=self._username, device_id=device_id),
        )

    def device_play_sound(self, *, device_id: str, subject: str) -> None:
        self._run_with_operation(
            operation="devices.play_sound",
            call=lambda: self._bundle.devices.play_sound(username=self._username, device_id=device_id, subject=subject),
        )

    def device_message(self, *, device_id: str, subject: str, message: str, sounds: bool) -> None:
        self._run_with_operation(
            operation="devices.message",
            call=lambda: self._bundle.devices.display_message(
                username=self._username,
                device_id=device_id,
                subject=subject,
                message=message,
                sounds=sounds,
            ),
        )

    def device_lost_mode(self, *, device_id: str, number: str, text: str, newpasscode: str) -> None:
        self._run_with_operation(
            operation="devices.lost_mode",
            call=lambda: self._bundle.devices.lost_mode(
                username=self._username,
                device_id=device_id,
                number=number,
                text=text,
                newpasscode=newpasscode,
            ),
        )

    def account_devices(self) -> Sequence[Mapping[str, Any]]:
        return self._run_with_operation(
            operation="account.devices",
            call=lambda: self._bundle.accounts.account_devices(username=self._username),
        )

    def account_family(self) -> Sequence[Mapping[str, Any]]:
        return self._run_with_operation(
            operation="account.family",
            call=lambda: self._bundle.accounts.account_family(username=self._username),
        )

    def account_storage(self) -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="account.storage",
            call=lambda: self._bundle.accounts.account_storage(username=self._username),
        )

    def drive_tree(self, *, path: str = "/") -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="drive.tree",
            call=lambda: self._bundle.drive.tree(username=self._username, path=path),
        )

    def drive_file_metadata(self, *, path: str) -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="drive.file_metadata",
            call=lambda: self._bundle.drive.file_metadata(username=self._username, path=path),
        )

    def drive_file_content(self, *, path: str) -> bytes:
        return self._run_with_operation(
            operation="drive.file_content",
            call=lambda: self._bundle.drive.file_content(username=self._username, path=path),
        )

    def drive_create_folder(self, *, parent_path: str, name: str) -> None:
        self._run_with_operation(
            operation="drive.create_folder",
            call=lambda: self._bundle.drive.create_folder(username=self._username, parent_path=parent_path, name=name),
        )

    def drive_upload_file(self, *, parent_path: str, filename: str, content: bytes) -> None:
        self._run_with_operation(
            operation="drive.upload_file",
            call=lambda: self._bundle.drive.upload_file(
                username=self._username,
                parent_path=parent_path,
                filename=filename,
                content=content,
            ),
        )

    def drive_rename_node(self, *, path: str, new_name: str) -> None:
        self._run_with_operation(
            operation="drive.rename_node",
            call=lambda: self._bundle.drive.rename_node(username=self._username, path=path, new_name=new_name),
        )

    def drive_delete_node(self, *, path: str) -> None:
        self._run_with_operation(
            operation="drive.delete_node",
            call=lambda: self._bundle.drive.delete_node(username=self._username, path=path),
        )

    def calendar_calendars(self) -> Sequence[Mapping[str, Any]]:
        return self._run_with_operation(
            operation="calendar.calendars",
            call=lambda: self._bundle.calendars.calendars(username=self._username),
        )

    def calendar_events(
        self,
        *,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> Sequence[Mapping[str, Any]]:
        return self._run_with_operation(
            operation="calendar.events",
            call=lambda: self._bundle.calendars.events(
                username=self._username,
                from_dt=from_dt,
                to_dt=to_dt,
            ),
        )

    def calendar_event_detail(self, *, calendar_guid: str, event_guid: str) -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="calendar.event_detail",
            call=lambda: self._bundle.calendars.event_detail(
                username=self._username,
                calendar_guid=calendar_guid,
                event_guid=event_guid,
            ),
        )

    def contacts_all(self) -> Sequence[Mapping[str, Any]]:
        return self._run_with_operation(
            operation="contacts.all",
            call=lambda: self._bundle.contacts.all_contacts(username=self._username),
        )

    def reminders_lists(self) -> Mapping[str, Sequence[Mapping[str, Any]]]:
        return self._run_with_operation(
            operation="reminders.lists",
            call=lambda: self._bundle.reminders.reminder_lists(username=self._username),
        )

    def reminders_create(
        self,
        *,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        return self._run_with_operation(
            operation="reminders.create",
            call=lambda: self._bundle.reminders.create_reminder(
                username=self._username,
                title=title,
                description=description,
                collection=collection,
                due_date=due_date,
            ),
        )

    def photos_albums(self) -> Sequence[Mapping[str, Any]]:
        return self._run_with_operation(
            operation="photos.albums",
            call=lambda: self._bundle.photos.list_albums(username=self._username),
        )

    def photos_assets(
        self,
        *,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Mapping[str, Any]]:
        return self._run_with_operation(
            operation="photos.assets",
            call=lambda: self._bundle.photos.list_assets(
                username=self._username,
                album=album,
                limit=limit,
                offset=offset,
            ),
        )

    def photo_asset_metadata(self, *, asset_id: str, album: str = "All Photos") -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="photos.asset_metadata",
            call=lambda: self._bundle.photos.asset_metadata(
                username=self._username,
                asset_id=asset_id,
                album=album,
            ),
        )

    def photo_asset_content(self, *, asset_id: str, album: str = "All Photos", version: str = "original") -> bytes:
        return self._run_with_operation(
            operation="photos.asset_content",
            call=lambda: self._bundle.photos.asset_content(
                username=self._username,
                asset_id=asset_id,
                album=album,
                version=version,
            ),
        )

    def ubiquity_tree(self, *, path: str = "/") -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="ubiquity.tree",
            call=lambda: self._bundle.ubiquity.ubiquity_tree(username=self._username, path=path),
        )

    def ubiquity_file_metadata(self, *, path: str) -> Mapping[str, Any]:
        return self._run_with_operation(
            operation="ubiquity.file_metadata",
            call=lambda: self._bundle.ubiquity.ubiquity_file_metadata(username=self._username, path=path),
        )

    def ubiquity_file_content(self, *, path: str) -> bytes:
        return self._run_with_operation(
            operation="ubiquity.file_content",
            call=lambda: self._bundle.ubiquity.ubiquity_file_content(username=self._username, path=path),
        )

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(
            f"PyiCloudService surface `{name}` is not supported. "
            "Use `PyiCloudService.compatibility_policy()` to inspect supported/deprecated/removed surfaces."
        )

    def __repr__(self) -> str:
        return f"<PyiCloudServiceCompat username={self._username!r}>"
