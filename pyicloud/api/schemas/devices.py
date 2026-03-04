"""Device action schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DevicePlaySoundRequest(BaseModel):
    subject: str = Field(default="Find My iPhone Alert", min_length=1)


class DeviceMessageRequest(BaseModel):
    subject: str = Field(default="Find My iPhone Alert", min_length=1)
    message: str = Field(min_length=1)
    sounds: bool = False


class DeviceLostModeRequest(BaseModel):
    number: str = Field(min_length=1)
    text: str = Field(default="This iPhone has been lost. Please call me.", min_length=1)
    newpasscode: str = ""
