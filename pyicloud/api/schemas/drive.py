"""Drive request schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DriveCreateFolderRequest(BaseModel):
    parent_path: str = "/"
    name: str = Field(min_length=1)


class DriveRenameNodeRequest(BaseModel):
    path: str = Field(min_length=1)
    new_name: str = Field(min_length=1)
