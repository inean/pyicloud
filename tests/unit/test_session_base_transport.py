from __future__ import annotations

from unittest.mock import patch

import pytest

from pyicloud.constants import AppleCookies as Jar
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.sessions.validate import Validate
from tests.const import AUTHENTICATED_USER, SCNT, SESSION_ID, VALID_TOKEN


@pytest.fixture
def validate_settings() -> Settings:
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "session_id": SESSION_ID,
                },
                "token": {
                    "session": VALID_TOKEN,
                    "trust": VALID_TOKEN,
                },
                "client_settings": {
                    "scnt": SCNT,
                },
            },
        )


@pytest.fixture
def validate_cookies_with_domain_mismatch() -> Cookies:
    return Cookies.model_validate(
        {
            Jar.DSLANG: {"name": Jar.DSLANG, "value": "US-EN", "domain": ".apple.com"},
            Jar.SITE: {"name": Jar.SITE, "value": "USA", "domain": ".apple.com"},
            Jar.WEBAUTH_USER: {"name": Jar.WEBAUTH_USER, "value": "webauth_user", "domain": ".apple.com"},
            Jar.WEBAUTH_TOKEN: {"name": Jar.WEBAUTH_TOKEN, "value": VALID_TOKEN, "domain": ".apple.com"},
            Jar.WEBAUTH_VALIDATE: {
                "name": Jar.WEBAUTH_VALIDATE,
                "value": VALID_TOKEN,
                "domain": ".apple.com",
            },
            Jar.WEB_SESSION_TOKEN: {
                "name": Jar.WEB_SESSION_TOKEN,
                "value": "session_token",
                "domain": ".apple.com",
            },
        },
    )


def test_dump_headers_casts_non_string_values(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
    monkeypatch: pytest.MonkeyPatch,
):
    user = Validate(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)

    settings_cls = type(user._settings)
    monkeypatch.setattr(
        settings_cls,
        "model_dump_by_meta",
        lambda self, *args, **kwargs: {
            "x-bool": True,
            "x-int": 42,
            "x-string": "ok",
        },
    )

    headers = user.dump_headers()

    assert headers["x-bool"] == "true"
    assert headers["x-int"] == "42"
    assert headers["x-string"] == "ok"


def test_create_request_rebinds_locale_domains_and_warns_for_non_locale_cookies(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
    caplog: pytest.LogCaptureFixture,
):
    user = Validate(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)

    with caplog.at_level("WARNING"):
        request = user.request.create_request()

    cookie_header = request.headers.get("cookie", "")
    assert Jar.DSLANG in cookie_header
    assert Jar.SITE in cookie_header
    assert Jar.WEBAUTH_USER in cookie_header

    warnings = [record.message for record in caplog.records if "domain mismatch" in record.message]
    assert any(Jar.WEBAUTH_USER in message for message in warnings)
    assert not any(Jar.DSLANG in message for message in warnings)
    assert not any(Jar.SITE in message for message in warnings)
