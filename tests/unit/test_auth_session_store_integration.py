from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pyicloud.contexts.crosscutting.auth.application.auth_session import AuthSessionService
from pyicloud.domain import AuthFlowRequest
from pyicloud.ports import AuthSessionPort


class FakeAuth(AuthSessionPort):
    async def signin(self, *, refresh_signin: bool) -> bool:
        return False

    async def security_code(self, code: str) -> None:
        raise AssertionError("security_code should not be called for non-2FA scenario")

    async def trust(self) -> None:
        raise AssertionError("trust should not be called for non-2FA scenario")

    async def account_login(self, *, require_trust_token: bool) -> None:
        return None

    async def session_validate(self) -> Mapping[str, Any]:
        return {"webservices": {"findme": {"status": "active", "url": "https://example.test"}}}


class SpyStore:
    def __init__(self):
        self.saved: dict[str, Mapping[str, Any]] = {}

    def load(self, account_id: str) -> Mapping[str, Any] | None:
        return self.saved.get(account_id)

    def save(self, account_id: str, payload: Mapping[str, Any]) -> None:
        self.saved[account_id] = payload

    def clear(self, account_id: str) -> None:
        self.saved.pop(account_id, None)


@pytest.mark.asyncio
async def test_auth_session_service_saves_validated_payload():
    store = SpyStore()
    service = AuthSessionService(auth=FakeAuth(), store=store)

    result = await service.run("acc-123", AuthFlowRequest())

    assert result.session_active is True
    assert store.saved["acc-123"]["webservices"]["findme"]["status"] == "active"
