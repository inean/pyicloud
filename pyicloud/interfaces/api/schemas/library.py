"""Schemas for library/file metadata payloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field


class DriveFileMetadataResponse(BaseModel):
    path: str = Field(min_length=1)
    name: str = Field(min_length=1)
    type: str = Field(min_length=1)
    size: int | None = None
    date_changed: str | None = None
    date_modified: str | None = None
    date_last_open: str | None = None


class PhotoAssetMetadataResponse(BaseModel):
    id: str = Field(min_length=1)
    album: str = Field(min_length=1)
    filename: str = Field(min_length=1)
    size: int
    created: str | None = None
    width: int
    height: int
    versions: Mapping[str, Mapping[str, Any]]


class UbiquityFileMetadataResponse(BaseModel):
    path: str = Field(min_length=1)
    item_id: int | str
    name: str = Field(min_length=1)
    type: str = Field(min_length=1)
    size: int | None = None
    modified: str | None = None
