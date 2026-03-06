"""Legacy-backed adapter for account domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pyicloud.ports import AccountServicePort

from .clients.account import AccountClient, LegacyAccountClient
from .mappers.account import map_account_device, map_account_family_member, map_account_storage
from .runtime import LegacyServicesAdapterBase


class AccountServiceAdapter(LegacyServicesAdapterBase, AccountServicePort):
    """Map account operations to the account service port contract."""

    def _account_client(self, *, username: str) -> AccountClient:
        return LegacyAccountClient(runtime=self._runtime, username=username)

    async def account_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        views = await self._run_blocking(lambda: self._account_client(username=username).devices())
        return [map_account_device(view) for view in views]

    async def account_family(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        views = await self._run_blocking(lambda: self._account_client(username=username).family())
        return [map_account_family_member(view) for view in views]

    async def account_storage(self, *, username: str) -> Mapping[str, Any]:
        storage = await self._run_blocking(lambda: self._account_client(username=username).storage())
        return map_account_storage(storage)
