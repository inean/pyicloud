"""Pydantic schemas used by FastAPI route handlers."""

from .account import AccountStorageResponse
from .auth import (
    AuthLoginRequest,
    AuthLoginResponse,
    AuthSecurityCodeRequest,
    AuthSessionResponse,
    SimpleOkResponse,
)
from .devices import DeviceLostModeRequest, DeviceMessageRequest, DevicePlaySoundRequest
from .drive import DriveCreateFolderRequest, DriveRenameNodeRequest
from .reminders import ReminderCreateRequest

__all__ = [
    "AccountStorageResponse",
    "AuthLoginRequest",
    "AuthLoginResponse",
    "AuthSecurityCodeRequest",
    "AuthSessionResponse",
    "DeviceLostModeRequest",
    "DeviceMessageRequest",
    "DevicePlaySoundRequest",
    "DriveCreateFolderRequest",
    "DriveRenameNodeRequest",
    "ReminderCreateRequest",
    "SimpleOkResponse",
]
