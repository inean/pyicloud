from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from pyicloud.models.cookies import Cookies
from pyicloud.models.errors import Error
from pyicloud.models.settings import Settings
from pyicloud.trees.setup import SetupHooks, SetupModelTree
from tests.const import AUTHENTICATED_USER, SCNT, SESSION_ID, VALID_PASSWORD, VALID_TOKEN


class DummyHooks(SetupHooks):
    def __init__(self) -> None:
        self.security_errors: list[tuple[int, str]] = []

    def get_password(self, username: str) -> str:
        return VALID_PASSWORD

    def get_security_code(self, device=None) -> str:  # noqa: ANN001
        return "123456"

    def get_trusted_device(self, devices):  # noqa: ANN001
        return None

    def on_security_code_error(self, error: Error) -> None:
        self.security_errors.append((error.code, error.message))


@pytest.fixture
def setup_settings() -> Settings:
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
                },
                "client_settings": {
                    "scnt": SCNT,
                },
            },
        )


@pytest.fixture
def setup_cookies_without_aasp() -> Cookies:
    return Cookies.model_validate(
        {
            "dslang": {"name": "dslang", "value": "US-EN"},
            "site": {"name": "site", "value": "USA"},
            "acn01": {"name": "acn01", "value": "acn01_value"},
        }
    )


@pytest.fixture
def setup_tree(setup_settings: Settings, setup_cookies_without_aasp: Cookies) -> SetupModelTree:
    return SetupModelTree(settings=setup_settings, cookies=setup_cookies_without_aasp, hooks=DummyHooks())


async def test_security_code_preconditions_allow_missing_aasp(setup_tree: SetupModelTree):
    setup_tree.settings.client_settings.scnt = SCNT
    setup_tree.settings.account.session_id = SESSION_ID
    setup_tree.cookies = Cookies.model_validate(
        {
            "dslang": {"name": "dslang", "value": "US-EN"},
            "site": {"name": "site", "value": "USA"},
            "acn01": {"name": "acn01", "value": "acn01_value"},
        }
    )
    assert await setup_tree.security_code_are_preconditions_met() is True


async def test_security_code_required_if_response_marks_trust_eligible(setup_tree: SetupModelTree):
    response = SimpleNamespace(headers=SimpleNamespace(trust_token_eligible=True))
    assert await setup_tree.is_security_code_required(response=response) is True


async def test_security_code_required_if_missing_trust_token_with_session(setup_tree: SetupModelTree):
    setup_tree.settings.client_settings.trust_eligible = True
    setup_tree.settings.token.session = VALID_TOKEN
    setup_tree.settings.token.trust = None

    assert await setup_tree.is_security_code_required(response=None) is True


class _FakeResponse:
    status_code = 200
    errors = []

    def __bool__(self):
        return True


class _FakeRequest:
    @staticmethod
    def create_request() -> httpx.Request:
        return httpx.Request("POST", "https://setup.icloud.com/setup/ws/1/accountLogin")


class _FakeAccountLogin:
    calls = 0

    def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
        self.request = _FakeRequest()
        self.response = _FakeResponse()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001
        return None

    async def send(self, request: httpx.Request) -> httpx.Response:
        _FakeAccountLogin.calls += 1
        return httpx.Response(200, request=request)


async def test_account_login_without_trust_token_does_not_fail_early(
    setup_tree: SetupModelTree,
    monkeypatch: pytest.MonkeyPatch,
):
    setup_tree.settings.client_settings.trust_eligible = True
    setup_tree.settings.token.trust = None

    monkeypatch.setattr("pyicloud.trees.setup.AccountLogin", _FakeAccountLogin)

    response = await setup_tree.account_login(require_trust_token=True)

    assert _FakeAccountLogin.calls == 1
    assert bool(response) is True


class _FailedResponseWithoutErrors:
    status_code = 500
    errors: list = []

    def __bool__(self) -> bool:
        return False


async def test_security_code_reset_uses_fallback_error_when_error_list_is_empty(setup_tree: SetupModelTree) -> None:
    setup_tree.blackboard["security_code"] = "123456"
    response = _FailedResponseWithoutErrors()

    reset = await setup_tree.security_code_reset(response=response)  # type: ignore[arg-type]

    assert reset is True
    assert "security_code" not in setup_tree.blackboard
    assert setup_tree.hooks.security_errors == [(500, "HTTP 500 error response.")]
