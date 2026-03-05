"""Domain mappers for typed account client views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.adapters.services.clients.account import AccountDeviceView, AccountStorageView, FamilyMemberView


def map_account_device(view: AccountDeviceView) -> Mapping[str, Any]:
    return dict(view.payload)


def map_account_family_member(view: FamilyMemberView) -> Mapping[str, Any]:
    return dict(view.payload)


def map_account_storage(view: AccountStorageView) -> Mapping[str, Any]:
    return {
        "usage": {
            "comp_storage_in_bytes": view.usage.comp_storage_in_bytes,
            "used_storage_in_bytes": view.usage.used_storage_in_bytes,
            "used_storage_in_percent": view.usage.used_storage_in_percent,
            "available_storage_in_bytes": view.usage.available_storage_in_bytes,
            "available_storage_in_percent": view.usage.available_storage_in_percent,
            "total_storage_in_bytes": view.usage.total_storage_in_bytes,
            "commerce_storage_in_bytes": view.usage.commerce_storage_in_bytes,
            "quota_over": view.usage.quota_over,
            "quota_tier_max": view.usage.quota_tier_max,
            "quota_almost_full": view.usage.quota_almost_full,
            "quota_paid": view.usage.quota_paid,
        },
        "usages_by_media": {
            key: {
                "key": media.key,
                "label": media.label,
                "color": media.color,
                "usage_in_bytes": media.usage_in_bytes,
            }
            for key, media in view.usages_by_media.items()
        },
    }
