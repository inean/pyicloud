"""Typed DTO contracts for core service domain operations."""

from __future__ import annotations

from typing import Any, NotRequired, TypedDict


class DeviceRecordDTO(TypedDict, total=False):
    id: str
    name: str
    deviceClass: str
    batteryLevel: float | None
    batteryStatus: str | None
    latitude: float | None
    longitude: float | None
    location: dict[str, Any]


class AccountDeviceDTO(TypedDict, total=False):
    id: str
    name: str
    model: str
    deviceClass: str


class AccountFamilyMemberDTO(TypedDict, total=False):
    fullName: str
    firstName: str
    lastName: str
    appleId: str
    dsid: str


class AccountStorageUsageDTO(TypedDict):
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


class AccountStorageMediaUsageDTO(TypedDict):
    key: str
    label: str
    color: str
    usage_in_bytes: int


class AccountStorageDTO(TypedDict):
    usage: AccountStorageUsageDTO
    usages_by_media: dict[str, AccountStorageMediaUsageDTO]


class DriveNodeChildDTO(TypedDict, total=False):
    name: str
    type: str
    path: str


class DriveNodeDTO(TypedDict):
    path: str
    name: str
    type: str
    size: int | None
    date_changed: str | None
    date_modified: str | None
    date_last_open: str | None
    children: NotRequired[list[DriveNodeChildDTO]]
