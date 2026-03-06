"""Contacts application service."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from pyicloud.contexts.services.contracts.services import ContactsServicePort
from pyicloud.domain import ContactDTO
from pyicloud.platform.telemetry.upstream import bind_upstream_context


class ContactsApplicationService:
    """Orchestrate contacts operations over the contacts outbound port."""

    def __init__(self, *, port: ContactsServicePort):
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

    async def all_contacts(self, *, username: str) -> Sequence[ContactDTO]:
        return await self._run_with_operation(
            username=username,
            operation="contacts.all",
            call=lambda: self._port.all_contacts(username=username),
        )
