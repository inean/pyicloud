"""Legacy-backed adapter for account domain operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pyicloud.ports import AccountServicePort

from .runtime import LegacyServicesAdapterBase


class AccountServiceAdapter(LegacyServicesAdapterBase, AccountServicePort):
    """Map account operations to the account service port contract."""

    def account_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        return [dict(item) for item in self._services(username=username).account.devices]

    def account_family(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        family = self._services(username=username).account.family
        return [dict(getattr(member, "_attrs", {})) for member in family]

    def account_storage(self, *, username: str) -> Mapping[str, Any]:
        storage = self._services(username=username).account.storage
        usage = storage.usage
        return {
            "usage": {
                "comp_storage_in_bytes": usage.comp_storage_in_bytes,
                "used_storage_in_bytes": usage.used_storage_in_bytes,
                "used_storage_in_percent": usage.used_storage_in_percent,
                "available_storage_in_bytes": usage.available_storage_in_bytes,
                "available_storage_in_percent": usage.available_storage_in_percent,
                "total_storage_in_bytes": usage.total_storage_in_bytes,
                "commerce_storage_in_bytes": usage.commerce_storage_in_bytes,
                "quota_over": usage.quota_over,
                "quota_tier_max": usage.quota_tier_max,
                "quota_almost_full": usage.quota_almost_full,
                "quota_paid": usage.quota_paid,
            },
            "usages_by_media": {
                key: {
                    "key": media.key,
                    "label": media.label,
                    "color": media.color,
                    "usage_in_bytes": media.usage_in_bytes,
                }
                for key, media in storage.usages_by_media.items()
            },
        }
