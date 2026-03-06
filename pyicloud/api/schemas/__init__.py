"""Pydantic schemas used by FastAPI route handlers."""

from .account import AccountStorageResponse
from .admin import (
    AllowlistEntryResponse,
    AllowlistListResponse,
    AllowlistRoleRequest,
    AllowlistUpsertRequest,
)
from .auth import (
    AuthChallengeRequest,
    AuthChallengeResponse,
    AuthLoginRequest,
    AuthLoginResponse,
    AuthSecurityCodeRequest,
    AuthSessionResponse,
    SimpleOkResponse,
)
from .common import ApiErrorDetail, DataEnvelope, ErrorEnvelope
from .devices import DeviceLostModeRequest, DeviceMessageRequest, DevicePlaySoundRequest
from .drive import DriveCreateFolderRequest, DriveRenameNodeRequest
from .library import DriveFileMetadataResponse, PhotoAssetMetadataResponse, UbiquityFileMetadataResponse
from .observability import ObservabilityQueryRequest, ObservabilityQueryResponse
from .reminders import ReminderCreateRequest

__all__ = [
    "AccountStorageResponse",
    "AllowlistEntryResponse",
    "AllowlistListResponse",
    "AllowlistRoleRequest",
    "AllowlistUpsertRequest",
    "AuthChallengeRequest",
    "AuthChallengeResponse",
    "AuthLoginRequest",
    "AuthLoginResponse",
    "AuthSecurityCodeRequest",
    "AuthSessionResponse",
    "ApiErrorDetail",
    "DataEnvelope",
    "DeviceLostModeRequest",
    "DeviceMessageRequest",
    "DevicePlaySoundRequest",
    "DriveCreateFolderRequest",
    "DriveFileMetadataResponse",
    "DriveRenameNodeRequest",
    "ErrorEnvelope",
    "ObservabilityQueryRequest",
    "ObservabilityQueryResponse",
    "PhotoAssetMetadataResponse",
    "ReminderCreateRequest",
    "SimpleOkResponse",
    "UbiquityFileMetadataResponse",
]
