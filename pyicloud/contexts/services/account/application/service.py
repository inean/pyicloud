"""Account application service."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from pyicloud.contexts.services.contracts.services import AccountServicePort
from pyicloud.domain import AccountDeviceDTO, AccountFamilyMemberDTO, AccountStorageDTO
from pyicloud.upstream import bind_upstream_context


class AccountApplicationService:
    """Orchestrate account operations over the account outbound port."""

    def __init__(self, *, port: AccountServicePort):
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

    async def account_devices(self, *, username: str) -> Sequence[AccountDeviceDTO]:
        return await self._run_with_operation(
            username=username,
            operation="account.devices",
            call=lambda: self._port.account_devices(username=username),
        )

    async def account_family(self, *, username: str) -> Sequence[AccountFamilyMemberDTO]:
        return await self._run_with_operation(
            username=username,
            operation="account.family",
            call=lambda: self._port.account_family(username=username),
        )

    async def account_storage(self, *, username: str) -> AccountStorageDTO:
        return await self._run_with_operation(
            username=username,
            operation="account.storage",
            call=lambda: self._port.account_storage(username=username),
        )
