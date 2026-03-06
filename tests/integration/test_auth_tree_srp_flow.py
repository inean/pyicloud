from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from pyicloud.adapters.auth import TreeAuthSessionAdapter
from pyicloud.contexts.crosscutting.auth.application.auth_session import AuthSessionService
from pyicloud.domain import AuthFlowRequest, AuthStep
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.trees.setup import SetupHooks, SetupModelTree
from tests.const import AUTHENTICATED_USER, REQUIRES_2FA_USER, VALID_2FA_CODE, VALID_PASSWORD
from tests.fakes.srp_auth_flow import SrpAuthFlowFake


class DummyHooks(SetupHooks):
    def get_password(self, username: str) -> str:
        return VALID_PASSWORD

    def get_security_code(self, device=None) -> str:  # noqa: ANN001
        return VALID_2FA_CODE

    def get_trusted_device(self, devices):  # noqa: ANN001
        return None


def _build_settings(username: str) -> Settings:
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": username,
                    "password": VALID_PASSWORD,
                },
            },
        )


def _build_setup_model(*, username: str, fake: SrpAuthFlowFake) -> SetupModelTree:
    class SetupModelWithFakeClient(SetupModelTree):
        tree_config = {
            "client": staticmethod(
                lambda **kwargs: httpx.AsyncClient(transport=httpx.MockTransport(fake.handler), **kwargs)
            ),
            "client_options": {},
        }

    cookies = Cookies.model_validate(
        {
            "dslang": {"name": "dslang", "value": "US-EN"},
            "site": {"name": "site", "value": "USA"},
        }
    )
    setup_model = SetupModelWithFakeClient(settings=_build_settings(username), cookies=cookies, hooks=DummyHooks())
    setup_model.password = VALID_PASSWORD
    setup_model.cookies["dslang"] = "US-EN"
    setup_model.cookies["site"] = "USA"
    return setup_model


@pytest.mark.asyncio
async def test_auth_flow_srp_without_2fa():
    fake = SrpAuthFlowFake(requires_2fa=False)
    setup_model = _build_setup_model(username=AUTHENTICATED_USER, fake=fake)
    auth_adapter = TreeAuthSessionAdapter(setup_model=setup_model)
    service = AuthSessionService(auth=auth_adapter)

    result = await service.run("acc-no-2fa", AuthFlowRequest(refresh_signin=True))

    assert result.steps == (
        AuthStep.SIGNIN,
        AuthStep.ACCOUNT_LOGIN,
        AuthStep.VALIDATE,
    )


@pytest.mark.asyncio
async def test_auth_flow_srp_with_2fa():
    fake = SrpAuthFlowFake(requires_2fa=True)
    setup_model = _build_setup_model(username=REQUIRES_2FA_USER, fake=fake)
    auth_adapter = TreeAuthSessionAdapter(setup_model=setup_model)
    service = AuthSessionService(auth=auth_adapter)

    result = await service.run(
        "acc-2fa",
        AuthFlowRequest(
            refresh_signin=True,
            security_code=VALID_2FA_CODE,
            require_trust_token=True,
        ),
    )

    assert result.steps == (
        AuthStep.SIGNIN,
        AuthStep.SECURITY_CODE,
        AuthStep.TRUST,
        AuthStep.ACCOUNT_LOGIN,
        AuthStep.VALIDATE,
    )
