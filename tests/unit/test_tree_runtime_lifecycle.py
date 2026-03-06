from __future__ import annotations

from unittest.mock import Mock, patch

from pyicloud.adapters.tree_runtime import FileBackedTreeRuntimeAdapter
from pyicloud.constants import AppleCookies as Jar
from pyicloud.log import PyiCloudPasswordFilter
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile
from pyicloud.trees.session import SessionModelTree
from tests.const import AUTHENTICATED_USER, SCNT, SESSION_ID, VALID_PASSWORD, VALID_TOKEN


class DummySessionTree(SessionModelTree):
    @property
    def bhtree(self):
        async def _noop():
            return True

        return _noop


def _build_settings(username: str = AUTHENTICATED_USER) -> Settings:
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": username,
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


def _build_cookies() -> Cookies:
    return Cookies.model_validate(
        {
            Jar.DSLANG: {"name": Jar.DSLANG, "value": "US-EN"},
            Jar.SITE: {"name": Jar.SITE, "value": "USA"},
            Jar.WEBAUTH_USER: {"name": Jar.WEBAUTH_USER, "value": "webauth_user"},
            Jar.WEBAUTH_TOKEN: {"name": Jar.WEBAUTH_TOKEN, "value": VALID_TOKEN},
            Jar.WEBAUTH_VALIDATE: {"name": Jar.WEBAUTH_VALIDATE, "value": VALID_TOKEN},
            Jar.WEB_SESSION_TOKEN: {"name": Jar.WEB_SESSION_TOKEN, "value": "session_token"},
        }
    )


def test_tree_runtime_lifecycle_is_explicit_and_reactive(monkeypatch):
    settings = _build_settings()
    cookies = _build_cookies()
    tree = DummySessionTree(settings=settings, cookies=cookies)

    settings_sync_calls: list[str] = []
    cookies_sync_calls: list[str] = []

    def _settings_loads(self, **kwargs):  # noqa: ANN001, ARG001
        settings_sync_calls.append("settings")
        return self._contents

    def _cookies_loads(self, **kwargs):  # noqa: ANN001
        cookies_sync_calls.append(str(kwargs.get("username", "")))
        return self._contents

    register_mock = Mock()
    unregister_mock = Mock()

    monkeypatch.setattr(SettingsFile, "loads", _settings_loads)
    monkeypatch.setattr(CookiesJar, "loads", _cookies_loads)
    monkeypatch.setattr(PyiCloudPasswordFilter, "register", register_mock)
    monkeypatch.setattr(PyiCloudPasswordFilter, "unregister", unregister_mock)

    settings.account.username = "no-runtime-yet@example.com"
    assert settings_sync_calls == []
    assert cookies_sync_calls == []
    assert register_mock.call_count == 0

    tree.set_runtime_port(FileBackedTreeRuntimeAdapter())
    tree.ensure_runtime_initialized()
    tree.ensure_runtime_initialized()

    assert settings_sync_calls == ["settings"]
    assert cookies_sync_calls == ["no-runtime-yet@example.com"]
    assert register_mock.call_count == 1

    settings.account.username = "runtime-active@example.com"
    assert settings_sync_calls == ["settings", "settings"]
    assert cookies_sync_calls == ["no-runtime-yet@example.com", "runtime-active@example.com"]

    tree.teardown_runtime()
    tree.teardown_runtime()
    settings.account.username = "runtime-detached@example.com"

    assert settings_sync_calls == ["settings", "settings"]
    assert cookies_sync_calls == ["no-runtime-yet@example.com", "runtime-active@example.com"]
    assert unregister_mock.call_count == 1
