"""Typed client for legacy account operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from pyicloud.platform.provider.runtime import ServiceRuntime


@dataclass(frozen=True)
class AccountDeviceView:
    payload: Mapping[str, object]


@dataclass(frozen=True)
class FamilyMemberView:
    payload: Mapping[str, object]


@dataclass(frozen=True)
class StorageUsageView:
    comp_storage_in_bytes: int
    used_storage_in_bytes: int
    used_storage_in_percent: float
    available_storage_in_bytes: int
    available_storage_in_percent: float
    total_storage_in_bytes: int
    commerce_storage_in_bytes: int
    quota_over: bool
    quota_tier_max: bool
    quota_almost_full: bool
    quota_paid: bool


@dataclass(frozen=True)
class MediaUsageView:
    key: str
    label: str
    color: str
    usage_in_bytes: int


@dataclass(frozen=True)
class AccountStorageView:
    usage: StorageUsageView
    usages_by_media: Mapping[str, MediaUsageView]


class AccountClient(Protocol):
    def devices(self) -> Sequence[AccountDeviceView]: ...
    def family(self) -> Sequence[FamilyMemberView]: ...
    def storage(self) -> AccountStorageView: ...


class LegacyAccountClient:
    """Query account domain data from legacy service objects with typed views."""

    def __init__(self, *, runtime: ServiceRuntime, username: str):
        self._runtime = runtime
        self._username = username

    def devices(self) -> Sequence[AccountDeviceView]:
        devices = self._runtime.services(username=self._username).account.devices
        return [AccountDeviceView(payload=dict(item)) for item in devices]

    def family(self) -> Sequence[FamilyMemberView]:
        family = self._runtime.services(username=self._username).account.family
        return [FamilyMemberView(payload=dict(getattr(member, "_attrs", {}))) for member in family]

    def storage(self) -> AccountStorageView:
        storage = self._runtime.services(username=self._username).account.storage
        usage = storage.usage
        usage_view = StorageUsageView(
            comp_storage_in_bytes=int(usage.comp_storage_in_bytes),
            used_storage_in_bytes=int(usage.used_storage_in_bytes),
            used_storage_in_percent=float(usage.used_storage_in_percent),
            available_storage_in_bytes=int(usage.available_storage_in_bytes),
            available_storage_in_percent=float(usage.available_storage_in_percent),
            total_storage_in_bytes=int(usage.total_storage_in_bytes),
            commerce_storage_in_bytes=int(usage.commerce_storage_in_bytes),
            quota_over=bool(usage.quota_over),
            quota_tier_max=bool(usage.quota_tier_max),
            quota_almost_full=bool(usage.quota_almost_full),
            quota_paid=bool(usage.quota_paid),
        )
        media_views = {
            str(key): MediaUsageView(
                key=str(media.key),
                label=str(media.label),
                color=str(media.color),
                usage_in_bytes=int(media.usage_in_bytes),
            )
            for key, media in storage.usages_by_media.items()
        }
        return AccountStorageView(usage=usage_view, usages_by_media=media_views)
