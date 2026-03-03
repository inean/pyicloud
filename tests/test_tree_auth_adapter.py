from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pyicloud.adapters.auth import TreeAuthSessionAdapter
from pyicloud.domain import SecurityCodeRequired


class FakeResponse:
    def __init__(self, ok: bool, *, body: Any = None, error: str | None = None):
        self._ok = ok
        self.body = body
        self.errors = []
        if error is not None:
            self.errors.append(SimpleNamespace(message=error))

    def __bool__(self):
        return self._ok


class FakeSetupModel:
    def __init__(
        self,
        *,
        signin_ok: bool = True,
        requires_security_code: bool = False,
        security_code_ok: bool = True,
        trust_ok: bool = True,
        account_login_ok: bool = True,
        session_validate_ok: bool = True,
        account_login_raises: Exception | None = None,
    ):
        self.calls: list[str] = []
        self.requires_security_code = requires_security_code
        self.signin_response = FakeResponse(signin_ok, error="signin error")
        self.security_code_response = FakeResponse(security_code_ok, error="bad code")
        self.trust_response = FakeResponse(trust_ok, error="trust error")
        self.account_login_response = FakeResponse(account_login_ok, error="account login error")
        self.session_validate_response = FakeResponse(
            session_validate_ok,
            body=SimpleNamespace(model_dump=lambda **_: {"webservices": {"findme": {"status": "active"}}}),
            error="validate error",
        )
        self.account_login_raises = account_login_raises

    async def signin(self, *, refresh_signin: bool):
        self.calls.append(f"signin:{refresh_signin}")
        return self.signin_response

    async def is_security_code_required(self, response):
        self.calls.append("is_security_code_required")
        return self.requires_security_code

    async def security_code(self, *, security_code: str):
        self.calls.append(f"security_code:{security_code}")
        return self.security_code_response

    async def trust(self):
        self.calls.append("trust")
        return self.trust_response

    async def account_login(self, *, require_trust_token: bool):
        self.calls.append(f"account_login:{require_trust_token}")
        if self.account_login_raises is not None:
            raise self.account_login_raises
        return self.account_login_response

    async def session_validate(self):
        self.calls.append("session_validate")
        return self.session_validate_response


@pytest.mark.asyncio
async def test_signin_reports_security_code_requirement():
    setup = FakeSetupModel(requires_security_code=True)
    adapter = TreeAuthSessionAdapter(setup_model=setup)  # type: ignore[arg-type]

    required = await adapter.signin(refresh_signin=False)

    assert required is True
    assert setup.calls == ["signin:False", "is_security_code_required"]


@pytest.mark.asyncio
async def test_security_code_maps_failure_to_domain_error():
    setup = FakeSetupModel(security_code_ok=False)
    adapter = TreeAuthSessionAdapter(setup_model=setup)  # type: ignore[arg-type]

    with pytest.raises(SecurityCodeRequired, match="bad code"):
        await adapter.security_code("123456")


@pytest.mark.asyncio
async def test_account_login_maps_trust_requirement_to_domain_error():
    setup = FakeSetupModel(account_login_raises=ValueError("Trust token is required"))
    adapter = TreeAuthSessionAdapter(setup_model=setup)  # type: ignore[arg-type]

    with pytest.raises(SecurityCodeRequired, match="Trust token is required"):
        await adapter.account_login(require_trust_token=True)


@pytest.mark.asyncio
async def test_session_validate_extracts_mapping_payload():
    setup = FakeSetupModel()
    adapter = TreeAuthSessionAdapter(setup_model=setup)  # type: ignore[arg-type]

    payload = await adapter.session_validate()

    assert payload["webservices"]["findme"]["status"] == "active"
