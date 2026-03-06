from __future__ import annotations

import pytest

from pyicloud.adapters.session import InMemoryApiSessionStore
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.contexts.crosscutting.auth.application.api_auth import AuthApiService
from pyicloud.domain import ChallengeExpired, InvalidChallengeTransition, SecurityCodeRequired


class _ScenarioAuthService:
    def __init__(self, *, scenario: str):
        self._scenario = scenario

    async def run(self, *, account_id: str, request):  # noqa: ANN001, ARG002
        if self._scenario == "requires_2fa":
            if str(request.security_code or "") == "123456":
                return None
            raise SecurityCodeRequired("security code required")
        if self._scenario == "invalid_credentials":
            raise RuntimeError("invalid credentials")
        return None


def _build_service() -> AuthApiService:
    session_store = InMemoryApiSessionStore()
    signer = JwtTokenSigner(secret="test-secret-at-least-thirty-two-bytes")

    def auth_service_factory(username: str, password: str):  # noqa: ARG001
        if username == "requires2fa@example.com":
            return _ScenarioAuthService(scenario="requires_2fa")
        if username == "invalid@example.com":
            return _ScenarioAuthService(scenario="invalid_credentials")
        return _ScenarioAuthService(scenario="success")

    return AuthApiService(
        token_signer=signer,
        session_query=session_store,
        session_command=session_store,
        auth_service_factory=auth_service_factory,
        enforce_allowlist=False,
    )


@pytest.mark.asyncio
async def test_challenge_start_returns_password_required() -> None:
    service = _build_service()

    payload = await service.challenge(username="success@example.com")

    assert payload["challenge_type"] == "password_required"
    assert payload["challenge_id"]
    assert payload["session_id"]
    assert payload["next_step"] == "password_envelope"


@pytest.mark.asyncio
async def test_challenge_password_step_authenticates_without_2fa() -> None:
    service = _build_service()

    payload = await service.challenge(
        username="success@example.com",
        password_envelope="secret",
    )

    assert payload["challenge_type"] == "authenticated"
    assert payload["access_token"]
    assert payload["session_id"]


@pytest.mark.asyncio
async def test_challenge_password_step_transitions_to_security_code() -> None:
    service = _build_service()

    payload = await service.challenge(
        username="requires2fa@example.com",
        password_envelope="secret",
    )

    assert payload["challenge_type"] == "security_code_required"
    assert payload["challenge_id"]
    assert payload["next_step"] == "security_code"


@pytest.mark.asyncio
async def test_challenge_security_code_step_authenticates() -> None:
    service = _build_service()
    first = await service.challenge(
        username="requires2fa@example.com",
        password_envelope="secret",
    )

    authenticated = await service.challenge(
        challenge_id=str(first["challenge_id"]),
        password_envelope="secret",
        security_code="123456",
    )

    assert authenticated["challenge_type"] == "authenticated"
    assert authenticated["access_token"]


@pytest.mark.asyncio
async def test_challenge_rejects_invalid_transition_inputs() -> None:
    service = _build_service()
    first = await service.challenge(username="success@example.com")

    with pytest.raises(InvalidChallengeTransition, match="password_required"):
        await service.challenge(
            challenge_id=str(first["challenge_id"]),
            security_code="123456",
        )


@pytest.mark.asyncio
async def test_challenge_rejects_username_or_session_mismatch() -> None:
    service = _build_service()
    first = await service.challenge(username="success@example.com")

    with pytest.raises(InvalidChallengeTransition, match="username does not match"):
        await service.challenge(
            challenge_id=str(first["challenge_id"]),
            username="other@example.com",
            password_envelope="secret",
        )

    with pytest.raises(InvalidChallengeTransition, match="session_id does not match"):
        await service.challenge(
            challenge_id=str(first["challenge_id"]),
            session_id="unexpected-session",
            password_envelope="secret",
        )


@pytest.mark.asyncio
async def test_challenge_step_is_single_use_after_completion() -> None:
    service = _build_service()
    first = await service.challenge(username="success@example.com")
    await service.challenge(
        challenge_id=str(first["challenge_id"]),
        password_envelope="secret",
    )

    with pytest.raises(ChallengeExpired, match="missing or expired"):
        await service.challenge(
            challenge_id=str(first["challenge_id"]),
            password_envelope="secret",
        )


@pytest.mark.asyncio
async def test_operation_resume_challenge_requires_password_before_auth() -> None:
    service = _build_service()
    issued = service.issue_operation_challenge(
        account_id="success@example.com",
        upstream_status=421,
        operation="GET /v1/devices",
        reason="session expired",
    )

    pending = await service.challenge(challenge_id=str(issued["challenge_id"]))
    assert pending["challenge_type"] == "operation_resume_required"
    assert pending["operation"] == "GET /v1/devices"

    completed = await service.challenge(
        challenge_id=str(issued["challenge_id"]),
        password_envelope="secret",
    )
    assert completed["challenge_type"] in {"authenticated", "security_code_required"}
