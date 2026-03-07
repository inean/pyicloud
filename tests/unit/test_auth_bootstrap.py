from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from pyicloud.domain import AuthFlowRequest
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.platform.composition.legacy_auth import build_auth_session_service
from pyicloud.platform.legacy_auth_tree.setup import SetupHooks


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
    def __init__(self, *, settings, cookies, hooks, context, auth_reset_policy=None):
        self.settings = settings
        self.cookies = cookies if cookies is not None else Cookies.model_validate({})
        self.hooks = hooks
        self.context = context or {}
        self.auth_reset_policy = auth_reset_policy

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


class FakeSetupModelWithRuntimeLifecycle(FakeSetupModel):
    last_instance: FakeSetupModelWithRuntimeLifecycle | None = None

    def __init__(self, *, settings, cookies, hooks, context, auth_reset_policy=None):
        super().__init__(
            settings=settings,
            cookies=cookies,
            hooks=hooks,
            context=context,
            auth_reset_policy=auth_reset_policy,
        )
        self.runtime_port = None
        self.runtime_initialized_calls = 0
        type(self).last_instance = self

    def set_runtime_port(self, runtime_port) -> None:  # noqa: ANN001
        self.runtime_port = runtime_port

    def has_runtime_port(self) -> bool:
        return self.runtime_port is not None

    def ensure_runtime_initialized(self) -> None:
        self.runtime_initialized_calls += 1


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


@pytest.mark.asyncio
async def test_build_auth_session_service_injects_runtime_port(tmp_path: Path):
    settings = Settings.create(username="runtime@example.com", password="secret")
    hooks = DummyHooks()
    service = build_auth_session_service(
        settings=settings,
        hooks=hooks,
        store_dir=tmp_path,
        setup_model_cls=FakeSetupModelWithRuntimeLifecycle,  # type: ignore[arg-type]
    )

    await service.run("runtime@example.com", AuthFlowRequest())

    instance = FakeSetupModelWithRuntimeLifecycle.last_instance
    assert instance is not None
    assert instance.runtime_port is not None
    assert instance.runtime_initialized_calls == 1
