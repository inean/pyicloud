"""Devices application service."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from pyicloud.contexts.services.contracts.services import DeviceServicePort
from pyicloud.domain import DeviceRecordDTO
from pyicloud.platform.telemetry.upstream import bind_upstream_context


class DevicesApplicationService:
    """Orchestrate device operations over the devices outbound port."""

    def __init__(self, *, port: DeviceServicePort):
        self._port = port

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
            call=lambda: self._port.list_devices(username=username),
        )

    async def location(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        return await self._run_with_operation(
            username=username,
            operation="devices.location",
            call=lambda: self._port.location(username=username, device_id=device_id),
        )

    async def status(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        return await self._run_with_operation(
            username=username,
            operation="devices.status",
            call=lambda: self._port.status(username=username, device_id=device_id),
        )

    async def play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        await self._run_with_operation(
            username=username,
            operation="devices.play_sound",
            call=lambda: self._port.play_sound(username=username, device_id=device_id, subject=subject),
        )

    async def message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        await self._run_with_operation(
            username=username,
            operation="devices.message",
            call=lambda: self._port.display_message(
                username=username,
                device_id=device_id,
                subject=subject,
                message=message,
                sounds=sounds,
            ),
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
        await self._run_with_operation(
            username=username,
            operation="devices.lost_mode",
            call=lambda: self._port.lost_mode(
                username=username,
                device_id=device_id,
                number=number,
                text=text,
                newpasscode=newpasscode,
            ),
        )
