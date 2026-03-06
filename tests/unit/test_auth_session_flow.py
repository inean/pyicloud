from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pyicloud.contexts.crosscutting.auth.application.auth_session import AuthSessionService
from pyicloud.domain import AuthFlowRequest, AuthStep, SecurityCodeRequired


class FakeAuthPort:
    def __init__(self, *, requires_2fa: bool, session_validate_failures: int = 0):
        self.requires_2fa = requires_2fa
        self.session_validate_failures = session_validate_failures
        self.calls: list[str] = []

    async def signin(self, *, refresh_signin: bool) -> bool:
        self.calls.append(f"signin:{refresh_signin}")
        return self.requires_2fa

    async def security_code(self, code: str) -> None:
        self.calls.append(f"security_code:{code}")

    async def trust(self) -> None:
        self.calls.append("trust")

    async def account_login(self, *, require_trust_token: bool) -> None:
        self.calls.append(f"account_login:{require_trust_token}")

    async def session_validate(self) -> Mapping[str, Any]:
        self.calls.append("validate")
        if self.session_validate_failures > 0:
            self.session_validate_failures -= 1
            raise RuntimeError("expired")
        return {"webservices": {"findme": {"status": "active", "url": "https://example.test"}}}


class FakeStore:
    def __init__(self):
        self.saved: dict[str, Mapping[str, Any]] = {}

    def load(self, account_id: str) -> Mapping[str, Any] | None:
        return self.saved.get(account_id)

    def save(self, account_id: str, payload: Mapping[str, Any]) -> None:
        self.saved[account_id] = payload

    def clear(self, account_id: str) -> None:
        self.saved.pop(account_id, None)


@pytest.mark.asyncio
async def test_auth_flow_parity_with_2fa():
    auth = FakeAuthPort(requires_2fa=True)
    store = FakeStore()
    service = AuthSessionService(auth=auth, store=store)

    result = await service.run(
        "acc-1",
        AuthFlowRequest(refresh_signin=True, security_code="123456", require_trust_token=True),
    )

    assert result.steps == (
        AuthStep.SIGNIN,
        AuthStep.SECURITY_CODE,
        AuthStep.TRUST,
        AuthStep.ACCOUNT_LOGIN,
        AuthStep.VALIDATE,
    )
    assert auth.calls == [
        "signin:True",
        "security_code:123456",
        "trust",
        "account_login:True",
        "validate",
    ]
    assert "acc-1" in store.saved


@pytest.mark.asyncio
async def test_auth_flow_parity_without_2fa():
    auth = FakeAuthPort(requires_2fa=False)
    service = AuthSessionService(auth=auth)

    result = await service.run("acc-2", AuthFlowRequest(refresh_signin=True))

    assert result.steps == (
        AuthStep.SIGNIN,
        AuthStep.ACCOUNT_LOGIN,
        AuthStep.VALIDATE,
    )
    assert auth.calls == [
        "signin:True",
        "account_login:True",
        "validate",
    ]


@pytest.mark.asyncio
async def test_auth_flow_requires_security_code_when_2fa():
    auth = FakeAuthPort(requires_2fa=True)
    service = AuthSessionService(auth=auth)

    with pytest.raises(SecurityCodeRequired):
        await service.run("acc-3", AuthFlowRequest(security_code=None))

    assert auth.calls == ["signin:True"]


@pytest.mark.asyncio
async def test_auth_flow_uses_validate_first_fast_path_for_renewal():
    auth = FakeAuthPort(requires_2fa=False)
    service = AuthSessionService(auth=auth)

    result = await service.run("acc-fast", AuthFlowRequest(refresh_signin=False))

    assert result.steps == (AuthStep.VALIDATE,)
    assert auth.calls == ["validate"]


@pytest.mark.asyncio
async def test_auth_flow_falls_back_to_full_signin_when_fast_path_fails():
    auth = FakeAuthPort(requires_2fa=False, session_validate_failures=1)
    service = AuthSessionService(auth=auth)

    result = await service.run("acc-fallback", AuthFlowRequest(refresh_signin=False))

    assert result.steps == (
        AuthStep.SIGNIN,
        AuthStep.ACCOUNT_LOGIN,
        AuthStep.VALIDATE,
    )
    assert auth.calls == [
        "validate",
        "signin:False",
        "account_login:True",
        "validate",
    ]
