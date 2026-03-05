from __future__ import annotations

from pyicloud.adapters.auth_state_reset import CookieAuthStateResetPolicy
from pyicloud.constants import AppleCookies as Jar
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from tests.const import AUTHENTICATED_USER, VALID_PASSWORD, VALID_TOKEN


def _settings() -> Settings:
    return Settings.create(username=AUTHENTICATED_USER, password=VALID_PASSWORD)


def test_cookie_auth_state_reset_policy_keeps_only_locale_cookies():
    cookies = Cookies.model_validate(
        {
            Jar.DSLANG: {"name": Jar.DSLANG, "value": "US-EN"},
            Jar.SITE: {"name": Jar.SITE, "value": "USA"},
            Jar.AASP: {"name": Jar.AASP, "value": "aasp"},
            Jar.ACN01: {"name": Jar.ACN01, "value": "acn01"},
            Jar.WEBAUTH_TOKEN: {"name": Jar.WEBAUTH_TOKEN, "value": VALID_TOKEN},
            "X_APPLE_WEB_KB-ABC": {"name": "X_APPLE_WEB_KB-ABC", "value": "1"},
        }
    )
    policy = CookieAuthStateResetPolicy()

    policy.reset_for_signin_retry(settings=_settings(), cookies=cookies)

    assert Jar.DSLANG in cookies
    assert Jar.SITE in cookies
    assert Jar.AASP not in cookies
    assert Jar.ACN01 not in cookies
    assert Jar.WEBAUTH_TOKEN not in cookies
    assert "X_APPLE_WEB_KB-ABC" not in cookies


def test_cookie_auth_state_reset_policy_is_idempotent():
    cookies = Cookies.model_validate(
        {
            Jar.DSLANG: {"name": Jar.DSLANG, "value": "US-EN"},
            Jar.SITE: {"name": Jar.SITE, "value": "USA"},
            Jar.WEBAUTH_VALIDATE: {"name": Jar.WEBAUTH_VALIDATE, "value": VALID_TOKEN},
        }
    )
    policy = CookieAuthStateResetPolicy()

    policy.reset_for_signin_retry(settings=_settings(), cookies=cookies)
    snapshot = cookies.model_dump(mode="python")
    policy.reset_for_signin_retry(settings=_settings(), cookies=cookies)

    assert cookies.model_dump(mode="python") == snapshot
