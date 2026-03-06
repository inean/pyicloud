"""Drive application service."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from pyicloud.contexts.services.contracts.services import DriveServicePort
from pyicloud.domain import DriveNodeDTO
from pyicloud.platform.telemetry.upstream import bind_upstream_context


class DriveApplicationService:
    """Orchestrate drive operations over the drive outbound port."""

    def __init__(self, *, port: DriveServicePort):
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

    async def tree(self, *, username: str, path: str) -> DriveNodeDTO:
        return await self._run_with_operation(
            username=username,
            operation="drive.tree",
            call=lambda: self._port.tree(username=username, path=path),
        )

    async def file_metadata(self, *, username: str, path: str) -> DriveNodeDTO:
        return await self._run_with_operation(
            username=username,
            operation="drive.file_metadata",
            call=lambda: self._port.file_metadata(username=username, path=path),
        )

    async def file_content(self, *, username: str, path: str) -> bytes:
        return await self._run_with_operation(
            username=username,
            operation="drive.file_content",
            call=lambda: self._port.file_content(username=username, path=path),
        )

    async def create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        await self._run_with_operation(
            username=username,
            operation="drive.create_folder",
            call=lambda: self._port.create_folder(username=username, parent_path=parent_path, name=name),
        )

    async def upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        await self._run_with_operation(
            username=username,
            operation="drive.upload_file",
            call=lambda: self._port.upload_file(
                username=username,
                parent_path=parent_path,
                filename=filename,
                content=content,
            ),
        )

    async def rename_node(self, *, username: str, path: str, new_name: str) -> None:
        await self._run_with_operation(
            username=username,
            operation="drive.rename_node",
            call=lambda: self._port.rename_node(username=username, path=path, new_name=new_name),
        )

    async def delete_node(self, *, username: str, path: str) -> None:
        await self._run_with_operation(
            username=username,
            operation="drive.delete_node",
            call=lambda: self._port.delete_node(username=username, path=path),
        )
