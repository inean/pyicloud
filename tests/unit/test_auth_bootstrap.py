from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from pyicloud.bootstrap import build_auth_session_service
from pyicloud.domain import AuthFlowRequest
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.trees.setup import SetupHooks


class DummyHooks(SetupHooks):
    def get_password(self, username: str) -> str:
        return "password"

    def get_security_code(self, device=None) -> str:
        return "123456"

    def get_trusted_device(self, devices):
        return None


class FakeResponse:
    def __init__(self, ok: bool, *, body=None):
        self._ok = ok
        self.body = body
        self.errors = []

    def __bool__(self):
        return self._ok


class FakeSetupModel:
    def __init__(self, *, settings, cookies, hooks, context):
        self.settings = settings
        self.cookies = cookies if cookies is not None else Cookies.model_validate({})
        self.hooks = hooks
        self.context = context or {}

    async def signin(self, *, refresh_signin: bool):
        return FakeResponse(True)

    async def is_security_code_required(self, response):
        return False

    async def security_code(self, *, security_code: str):
        return FakeResponse(True)

    async def trust(self):
        return FakeResponse(True)

    async def account_login(self, *, require_trust_token: bool):
        return FakeResponse(True)

    async def session_validate(self):
        payload = {"webservices": {"findme": {"status": "active", "url": "https://example.test"}}}
        return FakeResponse(True, body=SimpleNamespace(model_dump=lambda **_: payload))


@pytest.mark.asyncio
async def test_build_auth_session_service_persists_payload(tmp_path: Path):
    settings = Settings.create(username="user@example.com", password="secret")
    hooks = DummyHooks()
    service = build_auth_session_service(
        settings=settings,
        hooks=hooks,
        store_dir=tmp_path,
        setup_model_cls=FakeSetupModel,  # type: ignore[arg-type]
    )

    result = await service.run("user@example.com", AuthFlowRequest())

    assert result.session_active is True
    session_file = tmp_path / "userexamplecom.json"
    assert session_file.exists()
    payload = json.loads(session_file.read_text(encoding="utf-8"))
    assert payload["webservices"]["findme"]["status"] == "active"
