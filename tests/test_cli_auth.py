from __future__ import annotations

from types import SimpleNamespace

import pytest

from pyicloud.cli_auth import run_bootstrap_auth
from pyicloud.domain import SecurityCodeRequired


class FakeService:
    def __init__(self, responses):
        self._responses = iter(responses)
        self.calls = []

    async def run(self, *, account_id, request):
        self.calls.append((account_id, request))
        result = next(self._responses)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.mark.asyncio
async def test_run_bootstrap_auth_without_2fa():
    service = FakeService([SimpleNamespace(session_active=True)])

    result = await run_bootstrap_auth(
        username="user@example.com",
        password="secret",
        interactive=False,
        settings_factory=lambda *_: object(),  # type: ignore[return-value]
        service_builder=lambda **_: service,  # type: ignore[return-value]
    )

    assert result.session_active is True
    assert len(service.calls) == 1
    assert service.calls[0][1].security_code is None


@pytest.mark.asyncio
async def test_run_bootstrap_auth_retries_after_security_code():
    service = FakeService(
        [
            SecurityCodeRequired("Need code"),
            SimpleNamespace(session_active=True),
        ]
    )

    result = await run_bootstrap_auth(
        username="user@example.com",
        password="secret",
        interactive=True,
        security_code="123456",
        settings_factory=lambda *_: object(),  # type: ignore[return-value]
        service_builder=lambda **_: service,  # type: ignore[return-value]
    )

    assert result.session_active is True
    assert len(service.calls) == 2
    assert service.calls[0][1].security_code is None
    assert service.calls[1][1].security_code == "123456"


@pytest.mark.asyncio
async def test_run_bootstrap_auth_raises_when_non_interactive_requires_code():
    service = FakeService([SecurityCodeRequired("Need code")])

    with pytest.raises(SecurityCodeRequired):
        await run_bootstrap_auth(
            username="user@example.com",
            password="secret",
            interactive=False,
            settings_factory=lambda *_: object(),  # type: ignore[return-value]
            service_builder=lambda **_: service,  # type: ignore[return-value]
        )
