from __future__ import annotations

from time import time
from unittest.mock import patch

import pytest

from pyicloud.constants import AppleCookies as Jar
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.trees.session import SessionModelTree
from tests.const import AUTHENTICATED_USER, SCNT, SESSION_ID, VALID_PASSWORD, VALID_TOKEN


class DummySessionTree(SessionModelTree):
    def __init__(self, *, settings: Settings, cookies: Cookies | None = None):
        super().__init__(settings=settings, cookies=cookies)

    @property
    def bhtree(self):
        async def _noop():
            return True

        return _noop


@pytest.fixture
def tree_settings() -> Settings:
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "password": VALID_PASSWORD,
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
def valid_session_cookies() -> Cookies:
    return Cookies.model_validate(
        {
            Jar.DSLANG: {"name": Jar.DSLANG, "value": "US-EN"},
            Jar.SITE: {"name": Jar.SITE, "value": "USA"},
            Jar.WEBAUTH_USER: {"name": Jar.WEBAUTH_USER, "value": "webauth_user"},
            Jar.WEBAUTH_TOKEN: {"name": Jar.WEBAUTH_TOKEN, "value": VALID_TOKEN},
            Jar.WEBAUTH_VALIDATE: {"name": Jar.WEBAUTH_VALIDATE, "value": VALID_TOKEN},
            Jar.WEB_SESSION_TOKEN: {
                "name": Jar.WEB_SESSION_TOKEN,
                "value": "session_token",
            },
        }
    )


@pytest.fixture
def session_tree(tree_settings: Settings, valid_session_cookies: Cookies) -> DummySessionTree:
    return DummySessionTree(settings=tree_settings, cookies=valid_session_cookies)


def test_session_is_expired_when_required_cookie_missing(session_tree: DummySessionTree):
    session_tree.cookies.pop(Jar.WEBAUTH_VALIDATE, None)

    assert session_tree._session_is_expired() is True


def test_session_is_expired_when_required_cookie_is_expired(session_tree: DummySessionTree):
    session_tree.cookies[Jar.WEBAUTH_TOKEN] = VALID_TOKEN
    session_tree.cookies[Jar.WEBAUTH_TOKEN].expires = int(time()) - 60

    assert session_tree._session_is_expired() is True


def test_session_reset_cookies_removes_stale_and_dynamic_entries(
    session_tree: DummySessionTree,
):
    session_tree.cookies["aasp"] = "aasp_value"
    session_tree.cookies["acn01"] = "acn01_value"
    session_tree.cookies["X_APPLE_WEB_KB-ABC"] = "1"

    session_tree._session_reset_cookies()

    assert "aasp" not in session_tree.cookies
    assert "acn01" not in session_tree.cookies
    assert "X_APPLE_WEB_KB-ABC" not in session_tree.cookies
    assert "dslang" in session_tree.cookies
    assert "site" in session_tree.cookies
