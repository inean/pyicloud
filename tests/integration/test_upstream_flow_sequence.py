from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from pyicloud.adapters.auth import TreeAuthSessionAdapter
from pyicloud.adapters.session.legacy_service_http import LegacyServiceSessionAdapter
from pyicloud.application import AuthSessionService
from pyicloud.constants import AppleHeaders
from pyicloud.domain import AuthFlowRequest
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.ports import UpstreamErrorEvent, UpstreamRequestEvent, UpstreamResponseEvent
from pyicloud.trees.setup import SetupHooks, SetupModelTree
from pyicloud.upstream import bind_upstream_context
from tests.const import REQUIRES_2FA_USER, VALID_2FA_CODE, VALID_PASSWORD
from tests.fakes.srp_auth_flow import SrpAuthFlowFake


class _ProbeCollector:
    def __init__(self) -> None:
        self.requests: list[UpstreamRequestEvent] = []
        self.responses: list[UpstreamResponseEvent] = []
        self.errors: list[UpstreamErrorEvent] = []

    def on_request(self, event: UpstreamRequestEvent) -> None:
        self.requests.append(event)

    def on_response(self, event: UpstreamResponseEvent) -> None:
        self.responses.append(event)

    def on_error(self, event: UpstreamErrorEvent) -> None:
        self.errors.append(event)


class _DummyHooks(SetupHooks):
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
    setup_model = SetupModelWithFakeClient(settings=_build_settings(username), cookies=cookies, hooks=_DummyHooks())
    setup_model.password = VALID_PASSWORD
    setup_model.cookies["dslang"] = "US-EN"
    setup_model.cookies["site"] = "USA"
    return setup_model


@pytest.mark.integration
@pytest.mark.asyncio
async def test_upstream_probe_reconstructs_auth_then_find_devices_sequence(monkeypatch: pytest.MonkeyPatch, tmp_path):
    probe = _ProbeCollector()

    monkeypatch.setattr("pyicloud.sessions.get_upstream_probe", lambda: probe)
    monkeypatch.setattr("pyicloud.sessions.upstream_capture_body_max_bytes", lambda: 4096)
    monkeypatch.setattr("pyicloud.adapters.session.legacy_service_http.get_upstream_probe", lambda: probe)
    monkeypatch.setattr("pyicloud.adapters.session.legacy_service_http.upstream_capture_body_max_bytes", lambda: 4096)

    monkeypatch.setenv("PYICLOUD_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("PYICLOUD_COOKIES_DIR", str(tmp_path / "cookies"))

    fake = SrpAuthFlowFake(requires_2fa=True)
    setup_model = _build_setup_model(username=REQUIRES_2FA_USER, fake=fake)
    auth_adapter = TreeAuthSessionAdapter(setup_model=setup_model)
    auth_service = AuthSessionService(auth=auth_adapter)

    result = await auth_service.run(
        "acc-2fa",
        AuthFlowRequest(
            refresh_signin=True,
            security_code=VALID_2FA_CODE,
            require_trust_token=True,
        ),
    )

    def find_devices_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={
                AppleHeaders.REQUEST_ID: "req-find-1",
                "content-type": "application/json",
            },
            json={"content": []},
            request=request,
        )

    sync_settings = _build_settings(REQUIRES_2FA_USER)
    session = LegacyServiceSessionAdapter(
        settings=sync_settings,
        auth_callback=lambda *_args, **_kwargs: None,
        transport=httpx.MockTransport(find_devices_handler),
    )

    assert result.flow_id
    with bind_upstream_context(
        flow_id=result.flow_id,
        operation="devices.list",
        step="find_devices",
        username=REQUIRES_2FA_USER,
    ):
        response = session.request("POST", "https://p44-fmip.icloud.com/fmipservice/client/web/refreshClient", json={})
        assert response.status_code == 200

    assert probe.errors == []
    assert len(probe.responses) >= 6

    steps = [event["step"] for event in probe.responses]
    assert "signin" in steps
    assert "security_code" in steps
    assert "trust" in steps
    assert "account_login" in steps
    assert "validate" in steps
    assert steps[-1] == "find_devices"

    flow_ids = {event["flow_id"] for event in probe.responses}
    assert flow_ids == {result.flow_id}
