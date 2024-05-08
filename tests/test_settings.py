import locale
from datetime import datetime
from functools import lru_cache
from typing import cast
from unittest.mock import Mock
from zoneinfo import ZoneInfo, available_timezones

import pytest
import tzlocal
from hypothesis import HealthCheck, assume, given, settings
from hypothesis.strategies import (
    builds,
    characters,
    emails,
    from_regex,
    integers,
    sampled_from,
    text,
)
from psygnal import SignalGroup
from pydantic import SecretStr, ValidationError

from pyicloud.constants import ISO_3166_1_CODES, ISO_3166_1_CODES_3
from pyicloud.models.settings import Account, ClientSettings, Settings
from pyicloud.models.types import LeafModel

# Define a strategy for generating country values
country_code_strategy = from_regex(r"[A-Z]{3}", fullmatch=True)

# Define a strategy for generating the hours part
hours_strategy = integers(min_value=-12, max_value=12)

# Define a strategy for generating timezones
timezone_strategy = sampled_from(list(available_timezones()))


@lru_cache(maxsize=None)
def get_timezone_offset(tz: str) -> int:
    offset = datetime.now(ZoneInfo(tz)).utcoffset()
    return offset.seconds if offset else 0


@lru_cache(maxsize=None)
def get_gmt_offset(offset: int | str) -> str:
    if isinstance(offset, str):
        offset = get_timezone_offset(offset)
    # convert to hours and minutes in GMT format
    h = offset // (60 * 60)
    m = offset % (60 * 60)
    return f"GMT{h:+03d}:{m:02d}"


# Define a strategy for generating tuples of timezones and their real offsets from UTC
gmt_timezone_strategy = builds(lambda tz: (tz, get_gmt_offset(tz)), tz=timezone_strategy)

# Define a strategy for generating client id values
client_id_strategy = text(min_size=1, max_size=50)

# Define a strategy for generating scnt values
scnt_strategy = text(min_size=1, max_size=50)


# ACCOUNT TESTS
#


# Validators
@given(country=country_code_strategy)
def test_account_country_code_is_3166_3(country):
    try:
        Account.country_code_must_be_iso_3166_3(country)  # type: ignore
    except ValueError:
        assert country not in ISO_3166_1_CODES_3


@given(email=emails())
def test_account_username_must_be_email(email):
    account = Account(username=email, password="password")  # type: ignore
    assert account.username == email


@given(email=text(min_size=1, max_size=20, alphabet=characters(blacklist_characters="@")))
def test_account_invalid_email_raises_error(email):
    with pytest.raises(ValidationError):
        _ = Account(username=email, password="password")  # type: ignore


# Serializers
@given(secret=text(min_size=1, max_size=20), email=emails())
def test_account_dump_secret(secret, email):
    account = Account(username=email, password=secret)
    assert account.password and cast(SecretStr, account.password).get_secret_value() == secret


@given(secret=text(min_size=1, max_size=20), email=emails())
def test_account_model(secret, email):
    username = "test@example.com"
    password = "PassWord123!"
    country_code = "USA"
    account = Account(username=username, password=password, country_code=country_code)

    assert account.username == username
    assert account.password and cast(SecretStr, account.password).get_secret_value() == password
    assert account.country_code == country_code

    account.username = email
    assert account.username == email

    account.password = secret
    assert cast(SecretStr, account.password).get_secret_value() == secret


def test_account_json():
    account = Account(username="test@example.com", password="password", country_code="USA")  # type: ignore
    expected_json = '{"username":"test@example.com","password":"password","country_code":"USA"}'
    assert account.model_dump_json(exclude_unset=True) == expected_json


# CLIENT SETTINGS TESTS
#
@pytest.fixture(params=["en_US", "fr_FR", "de_DE", "es_CO", "it_IT"])
def dslang(monkeypatch, request):
    monkeypatch.setattr("locale.getlocale", lambda: (request.param, "UTF-8"))
    locale_code = locale.getlocale()[0] or "en_US"
    return f"{locale_code[3:]}-{locale_code[:2].upper()}"


@pytest.fixture
def site(dslang):
    return ISO_3166_1_CODES_3[ISO_3166_1_CODES.index(dslang[:2])]


def test_client_defaults():
    client_settings = ClientSettings()
    assert client_settings.timezone == tzlocal.get_localzone_name()
    assert client_settings.client_id.startswith("auth-")
    assert client_settings.time_offset == get_gmt_offset(client_settings.timezone)
    assert client_settings.scnt is None


def test_client_settings_timezone_default():
    client_settings = ClientSettings()
    expected_timezone = tzlocal.get_localzone_name()
    assert client_settings.timezone_default() == expected_timezone


def test_client_settings_dslang_default(dslang):
    client_settings = ClientSettings()
    assert client_settings.dslang_default() == dslang


def test_client_settings_site_default(site):
    client_settings = ClientSettings()
    assert client_settings.site_default() == site


def test_client_settings_invalid_tz():
    with pytest.raises(ValueError):
        ClientSettings(timezone="Invalid")


@given(timezone=timezone_strategy, client_id=client_id_strategy, scnt=scnt_strategy)
def test_client_settings(timezone, client_id, scnt):
    client_settings = ClientSettings(timezone=timezone, client_id=client_id, scnt=scnt)
    assert client_settings.timezone == timezone
    assert client_settings.client_id == client_id
    assert client_settings.scnt == scnt
    # check computed values
    assert client_settings.time_offset == get_gmt_offset(client_settings.timezone)  # type: ignore


@given(timezone=gmt_timezone_strategy)
def test_client_settings_time_offset(timezone):
    timezone, expected_offset = timezone
    client_settings = ClientSettings(timezone=timezone)
    assert client_settings.time_offset == expected_offset


def test_client_dump_json():
    client_settings = ClientSettings()
    expected_json = (
        f'{{"dslang":"{ClientSettings.dslang_default()}",'
        f'"site":"{ClientSettings.site_default()}",'
        f'"timezone":"{tzlocal.get_localzone_name()}",'
        f'"client_id":"{client_settings.client_id}"}}'
    )
    assert client_settings.model_dump_json(by_alias=True, exclude_none=True) == expected_json


class SubmodelTest(LeafModel):
    subfield: str = "subfield"


class SettingsTest(Settings):
    field: str = "field"
    submodel: SubmodelTest = SubmodelTest()


@given(username=emails())
def test_settings_construction(username):
    settings = SettingsTest(account={"username": username})  # type: ignore

    # Check that settings is an instance of both Settings and TestSettings
    assert isinstance(settings, Settings)
    assert isinstance(settings, SettingsTest)

    # Check that the account property is an instance of Account and has the correct username
    assert isinstance(settings.account, Account)
    assert settings.account.username == username

    # Check that the test property has been correctly set
    assert settings.field == "field"


@settings(max_examples=1, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(username=emails(), new_username=emails())
def test_settings_event_system(username, new_username):
    assume(username != new_username)
    settings = SettingsTest.create(username=username)
    assert settings.account.password is None
    settings.account.password = "password"
    assert cast(SecretStr, settings.account.password).get_secret_value() == "password"

    assert isinstance(settings.account.events, SignalGroup)
    assert isinstance(settings.token.events, SignalGroup)
    assert isinstance(settings.client_settings.events, SignalGroup)

    assert "subfield" in settings.submodel.events
    assert "username" in settings.account.events

    subfield_mock, account_mock = map(Mock, range(2))

    # Trigger the event on submodel
    settings.submodel.events.subfield.connect(subfield_mock)
    settings.submodel.subfield = new_username
    assert settings.submodel.subfield == new_username
    subfield_mock.assert_called_with(new_username)
    subfield_mock.reset_mock()
    settings.submodel.subfield = new_username
    subfield_mock.assert_not_called()

    # Trigger the event on account
    settings.account.events.username.connect(account_mock)
    settings.account.username = new_username
    assert settings.account.username == new_username
    account_mock.assert_called_with(new_username)
    account_mock.reset_mock()
    settings.account.username = new_username
    account_mock.assert_not_called()
