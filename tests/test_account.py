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
        yield PyiCloudServicesMock(api).account


def test_repr(service):
    """Tests representation."""
    assert repr(service) == "<AccountService: {devices: 2, family: 3, storage: 3020076244 bytes free}>"


def test_devices(service):
    """Tests devices."""
    assert service.devices
    assert len(service.devices) == 2

    for device in service.devices:
        assert device.name
        assert device.model
        assert device.udid
        assert device["serialNumber"]
        assert device["osVersion"]
        assert device["modelLargePhotoURL2x"]
        assert device["modelLargePhotoURL1x"]
        assert device["paymentMethods"]
        assert device["name"]
        assert device["model"]
        assert device["udid"]
        assert device["modelSmallPhotoURL2x"]
        assert device["modelSmallPhotoURL1x"]
        assert device["modelDisplayName"]
        assert repr(device) == "<AccountDevice: {model: " + device.model_display_name + ", name: " + device.name + "}>"


def test_family(service):
    """Tests family members."""
    assert service.family
    assert len(service.family) == 3

    for member in service.family:
        assert member.last_name
        assert member.dsid
        assert member.original_invitation_email
        assert member.full_name
        assert member.age_classification
        assert member.apple_id_for_purchases
        assert member.apple_id
        assert member.first_name
        assert not member.has_screen_time_enabled
        assert not member.has_ask_to_buy_enabled
        assert not member.share_my_location_enabled_family_members
        assert member.dsid_for_purchases
        assert (
            repr(member)
            == "<FamilyMember: {name: " + member.full_name + ", age_classification: " + member.age_classification + "}>"
        )


def test_storage(service):
    """Tests storage."""
    assert service.storage
    assert (
        repr(service.storage)
        == "<AccountStorage: {usage: 43.75% used of 5368709120 bytes, usages_by_media: OrderedDict({'photos': <AccountStorageUsageForMedia: {key: photos, usage: 0 bytes}>, 'backup': <AccountStorageUsageForMedia: {key: backup, usage: 799008186 bytes}>, 'docs': <AccountStorageUsageForMedia: {key: docs, usage: 449092146 bytes}>, 'mail': <AccountStorageUsageForMedia: {key: mail, usage: 1101522944 bytes}>})}>"
    )


def test_storage_usage(service):
    """Tests storage usage."""
    assert service.storage.usage
    usage = service.storage.usage
    assert usage.comp_storage_in_bytes or usage.comp_storage_in_bytes == 0
    assert usage.used_storage_in_bytes
    assert usage.used_storage_in_percent
    assert usage.available_storage_in_bytes
    assert usage.available_storage_in_percent
    assert usage.total_storage_in_bytes
    assert usage.commerce_storage_in_bytes or usage.commerce_storage_in_bytes == 0
    assert not usage.quota_over
    assert not usage.quota_tier_max
    assert not usage.quota_almost_full
    assert not usage.quota_paid
    assert (
        repr(usage)
        == "<AccountStorageUsage: "
        + str(usage.used_storage_in_percent)
        + "% used of "
        + str(usage.total_storage_in_bytes)
        + " bytes>"
    )


def test_storage_usages_by_media(service):
    """Tests storage usages by media."""
    assert service.storage.usages_by_media

    for usage_media in service.storage.usages_by_media.values():
        assert usage_media.key
        assert usage_media.label
        assert usage_media.color
        assert usage_media.usage_in_bytes or usage_media.usage_in_bytes == 0
        assert (
            repr(usage_media)
            == "<AccountStorageUsageForMedia: {key: "
            + usage_media.key
            + ", usage: "
            + str(usage_media.usage_in_bytes)
            + " bytes}>"
        )
