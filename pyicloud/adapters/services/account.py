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

    def _client(self, *, username: str) -> AccountClient:
        return LegacyAccountClient(runtime=self._runtime, username=username)

    def account_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return [map_account_device(view) for view in self._client(username=username).devices()]

    def account_family(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return [map_account_family_member(view) for view in self._client(username=username).family()]

    def account_storage(self, *, username: str) -> Mapping[str, Any]:
        return map_account_storage(self._client(username=username).storage())
