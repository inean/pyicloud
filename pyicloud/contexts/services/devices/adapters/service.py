"""Legacy-backed adapter for device domain operations."""

from __future__ import annotations

from collections.abc import Sequence

from pyicloud.adapters.services.clients.devices import DevicesClient, LegacyDevicesClient
from pyicloud.adapters.services.mappers.devices import map_device_location, map_device_snapshot, map_device_status
from pyicloud.adapters.services.runtime import ServicesAdapterBase
from pyicloud.contexts.services.contracts.services import DeviceServicePort
from pyicloud.domain import DeviceRecordDTO


class DevicesServiceAdapter(ServicesAdapterBase, DeviceServicePort):
    """Map Find My iPhone operations to the device service port contract."""

    def _devices_client(self, *, username: str) -> DevicesClient:
        return LegacyDevicesClient(runtime=self._runtime, username=username)

    async def list_devices(self, *, username: str) -> Sequence[DeviceRecordDTO]:
        snapshots = await self._run_blocking(lambda: self._devices_client(username=username).list_devices())
        return [map_device_snapshot(view) for view in snapshots]

    async def location(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        view = await self._run_blocking(lambda: self._devices_client(username=username).location(device_id=device_id))
        return map_device_location(view)

    async def status(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        view = await self._run_blocking(lambda: self._devices_client(username=username).status(device_id=device_id))
        return map_device_status(view)

    async def play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        await self._run_blocking(
            lambda: self._devices_client(username=username).play_sound(device_id=device_id, subject=subject)
        )

    async def display_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        await self._run_blocking(
            lambda: self._devices_client(username=username).display_message(
                device_id=device_id,
                subject=subject,
                message=message,
                sounds=sounds,
            )
        )

    async def lost_mode(
        self,
        *,
        username: str,
        device_id: str,
        number: str,
        text: str,
        newpasscode: str,
    ) -> None:
        await self._run_blocking(
            lambda: self._devices_client(username=username).lost_mode(
                device_id=device_id,
                number=number,
                text=text,
                newpasscode=newpasscode,
            )
        )
