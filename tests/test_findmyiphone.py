import re
from unittest.mock import patch

import pytest

from . import PyiCloudMock, PyiCloudServicesMock
from .const import AUTHENTICATED_USER, VALID_PASSWORD


@pytest.fixture
def username():
    return AUTHENTICATED_USER


@pytest.fixture
def config_file(tmp_path, username):
    return tmp_path / (re.sub(r"\W", "", username) + ".json")


@pytest.fixture
def service(username, config_file, monkeypatch):
    """Set up tests."""
    with patch("pyicloud.paths.AbstractPath.loads") as monkey_loads:
        monkey_loads.return_value = None
        monkeypatch.setenv("TEST_CONFIG_FILE", str(config_file))
        api = PyiCloudMock(username, VALID_PASSWORD)
        api.authenticate()
        yield PyiCloudServicesMock(api)


def test_devices(service):
    """Tests devices."""
    assert len(list(service.devices)) == 13

    for device in service.devices:
        assert device["canWipeAfterLock"] is not None
        assert device["baUUID"] is not None
        assert device["wipeInProgress"] is not None
        assert device["lostModeEnabled"] is not None
        assert device["activationLocked"] is not None
        assert device["passcodeLength"] is not None
        assert device["deviceStatus"] is not None
        assert device["features"] is not None
        assert device["lowPowerMode"] is not None
        assert device["rawDeviceModel"] is not None
        assert device["id"] is not None
        assert device["isLocating"] is not None
        assert device["modelDisplayName"] is not None
        assert device["lostTimestamp"] is not None
        assert device["batteryLevel"] is not None
        assert device["locationEnabled"] is not None
        assert device["locFoundEnabled"] is not None
        assert device["fmlyShare"] is not None
        assert device["lostModeCapable"] is not None
        assert device["wipedTimestamp"] is None
        assert device["deviceDisplayName"] is not None
        assert device["audioChannels"] is not None
        assert device["locationCapable"] is not None
        assert device["batteryStatus"] is not None
        assert device["trackingInfo"] is None
        assert device["name"] is not None
        assert device["isMac"] is not None
        assert device["thisDevice"] is not None
        assert device["deviceClass"] is not None
        assert device["deviceModel"] is not None
        assert device["maxMsgChar"] is not None
        assert device["darkWake"] is not None
        assert device["remoteWipe"] is None

        assert device.data["canWipeAfterLock"] is not None
        assert device.data["baUUID"] is not None
        assert device.data["wipeInProgress"] is not None
        assert device.data["lostModeEnabled"] is not None
        assert device.data["activationLocked"] is not None
        assert device.data["passcodeLength"] is not None
        assert device.data["deviceStatus"] is not None
        assert device.data["features"] is not None
        assert device.data["lowPowerMode"] is not None
        assert device.data["rawDeviceModel"] is not None
        assert device.data["id"] is not None
        assert device.data["isLocating"] is not None
        assert device.data["modelDisplayName"] is not None
        assert device.data["lostTimestamp"] is not None
        assert device.data["batteryLevel"] is not None
        assert device.data["locationEnabled"] is not None
        assert device.data["locFoundEnabled"] is not None
        assert device.data["fmlyShare"] is not None
        assert device.data["lostModeCapable"] is not None
        assert device.data["wipedTimestamp"] is None
        assert device.data["deviceDisplayName"] is not None
        assert device.data["audioChannels"] is not None
        assert device.data["locationCapable"] is not None
        assert device.data["batteryStatus"] is not None
        assert device.data["trackingInfo"] is None
        assert device.data["name"] is not None
        assert device.data["isMac"] is not None
        assert device.data["thisDevice"] is not None
        assert device.data["deviceClass"] is not None
        assert device.data["deviceModel"] is not None
        assert device.data["maxMsgChar"] is not None
        assert device.data["darkWake"] is not None
        assert device.data["remoteWipe"] is None
