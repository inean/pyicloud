"""Ubiquity application service."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from pyicloud.contexts.services.contracts.services import UbiquityServicePort
from pyicloud.domain import UbiquityNodeDTO
from pyicloud.platform.telemetry.upstream import bind_upstream_context


class UbiquityApplicationService:
    """Orchestrate ubiquity operations over the ubiquity outbound port."""

    def __init__(self, *, port: UbiquityServicePort):
        self._port = port

    @staticmethod
    async def _run_with_operation[T](
        *,
        username: str,
        operation: str,
        call: Callable[[], Awaitable[T]],
    ) -> T:
        with bind_upstream_context(username=username, operation=operation, step=operation.split(".")[-1]):
            return await call()

    async def ubiquity_tree(self, *, username: str, path: str) -> UbiquityNodeDTO:
        return await self._run_with_operation(
            username=username,
            operation="ubiquity.tree",
            call=lambda: self._port.ubiquity_tree(username=username, path=path),
        )

    async def ubiquity_file_metadata(self, *, username: str, path: str) -> UbiquityNodeDTO:
        return await self._run_with_operation(
            username=username,
            operation="ubiquity.file_metadata",
            call=lambda: self._port.ubiquity_file_metadata(username=username, path=path),
        )

    async def ubiquity_file_content(self, *, username: str, path: str) -> bytes:
        return await self._run_with_operation(
            username=username,
            operation="ubiquity.file_content",
            call=lambda: self._port.ubiquity_file_content(username=username, path=path),
        )
