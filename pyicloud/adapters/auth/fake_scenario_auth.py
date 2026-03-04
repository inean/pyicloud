"""Deterministic fake auth adapter for vertical API/CLI tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pyicloud.domain import SecurityCodeRequired
from pyicloud.ports import AuthSessionPort

FakeAuthScenario = Literal[
    "success",
    "requires_2fa",
    "invalid_credentials",
    "invalid_security_code",
    "expired_session",
]


class FakeScenarioAuthSessionAdapter(AuthSessionPort):
    """Scenario-driven auth adapter used to test auth flows without iCloud calls."""

    def __init__(
        self,
        *,
        scenario: FakeAuthScenario = "success",
        valid_security_code: str = "123456",
        payload: Mapping[str, Any] | None = None,
    ):
        self._scenario = scenario
        self._valid_security_code = valid_security_code
        self._security_verified = False
        self._payload = dict(
            payload
            or {
                "webservices": {
                    "findme": {"status": "active", "url": "https://findme.example.test"},
                    "account": {"status": "active", "url": "https://account.example.test"},
                    "drivews": {"status": "active", "url": "https://drive.example.test"},
                    "docws": {"status": "active", "url": "https://docws.example.test"},
                }
            }
        )

    async def signin(self, *, refresh_signin: bool) -> bool:  # noqa: ARG002
        if self._scenario == "invalid_credentials":
            raise RuntimeError("Invalid credentials")
        if self._scenario in {"requires_2fa", "invalid_security_code"} and not self._security_verified:
            return True
        return False

    async def security_code(self, code: str) -> None:
        if self._scenario == "invalid_security_code" and code != self._valid_security_code:
            raise SecurityCodeRequired("Invalid security code")
        if self._scenario == "requires_2fa" and code != self._valid_security_code:
            raise SecurityCodeRequired("Invalid security code")
        self._security_verified = True

    async def trust(self) -> None:
        return None

    async def account_login(self, *, require_trust_token: bool) -> None:  # noqa: ARG002
        if self._scenario == "invalid_credentials":
            raise RuntimeError("Account login failed")

    async def session_validate(self) -> Mapping[str, Any]:
        if self._scenario == "expired_session":
            raise RuntimeError("Session expired")
        return dict(self._payload)
