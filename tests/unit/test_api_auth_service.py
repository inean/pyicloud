from __future__ import annotations

from time import time
from typing import Any

import pytest

from pyicloud.contexts.crosscutting.auth.application.api_auth import AuthApiService
from pyicloud.domain import InvalidChallengeTransition, InvalidCredentials, SecurityCodeRequired, Unauthorized


class _FakeTokenSigner:
    def __init__(self, claims_by_token: dict[str, dict[str, Any]]):
        self._claims_by_token = claims_by_token

    def sign(self, *, subject: str, claims, expires_in_seconds: int):  # noqa: ANN001, ARG002
        token = f"token-{subject}"
        self._claims_by_token[token] = {
            "sub": subject,
            "jti": str(claims["jti"]),
            "exp": int(time()) + expires_in_seconds,
        }
        return token

    def verify(self, token: str):
        if token not in self._claims_by_token:
            raise RuntimeError("invalid")
        return dict(self._claims_by_token[token])


class _RecordingSessionStore:
    def __init__(self):
        self.challenges: dict[str, dict[str, Any]] = {}
        self.revoked_keys: set[str] = set()
        self.revoke_calls: list[tuple[str, int]] = []

    def get_challenge(self, challenge_id: str):
        return self.challenges.get(challenge_id)

    def is_token_revoked(self, token_id: str) -> bool:
        return token_id in self.revoked_keys

    def put_challenge(self, *, challenge_id: str, payload, ttl_seconds: int):  # noqa: ANN001, ARG002
        self.challenges[challenge_id] = dict(payload)

    def delete_challenge(self, challenge_id: str):
        self.challenges.pop(challenge_id, None)

    def revoke_token(self, *, token_id: str, ttl_seconds: int):
        self.revoked_keys.add(token_id)
        self.revoke_calls.append((token_id, ttl_seconds))


class _SecurityCodeRequiredAuthService:
    async def run(self, *, account_id: str, request):  # noqa: ANN001, ARG002
        raise SecurityCodeRequired("security code required")


class _SuccessAuthService:
    async def run(self, *, account_id: str, request):  # noqa: ANN001, ARG002
        return None


class _TwoFactorAuthService:
    async def run(self, *, account_id: str, request):  # noqa: ANN001, ARG002
        if str(request.security_code or "") == "123456":
            return None
        raise SecurityCodeRequired("security code required")


def _service_with_claims(claims_by_token: dict[str, dict[str, Any]], store: _RecordingSessionStore) -> AuthApiService:
    signer = _FakeTokenSigner(claims_by_token)
    return AuthApiService(
        token_signer=signer,
        session_query=store,
        session_command=store,
        auth_service_factory=lambda username, password: None,  # noqa: ARG005
    )


def test_session_revocation_is_account_scoped() -> None:
    future_expiry = int(time()) + 120
    claims_by_token = {
        "token-a": {"sub": "user-a@example.com", "jti": "shared-jti", "exp": future_expiry},
        "token-b": {"sub": "user-b@example.com", "jti": "shared-jti", "exp": future_expiry},
    }
    store = _RecordingSessionStore()
    store.revoked_keys.add("user-a@example.com:shared-jti")
    service = _service_with_claims(claims_by_token, store)

    with pytest.raises(Unauthorized, match="revoked"):
        service.session(token="token-a")
    principal = service.session(token="token-b")
    assert principal.username == "user-b@example.com"


def test_logout_revokes_account_scoped_key_with_minimum_ttl() -> None:
    claims_by_token = {
        "token-a": {"sub": "user-a@example.com", "jti": "token-id", "exp": int(time()) - 5},
    }
    store = _RecordingSessionStore()
    service = _service_with_claims(claims_by_token, store)

    service.logout(token="token-a")

    assert store.revoke_calls == [("user-a@example.com:token-id", 1)]


@pytest.mark.asyncio
async def test_login_challenge_does_not_persist_plaintext_password() -> None:
    claims_by_token: dict[str, dict[str, Any]] = {}
    store = _RecordingSessionStore()
    signer = _FakeTokenSigner(claims_by_token)
    service = AuthApiService(
        token_signer=signer,
        session_query=store,
        session_command=store,
        auth_service_factory=lambda username, password: _SecurityCodeRequiredAuthService(),  # noqa: ARG005
    )

    payload = await service.login(username="requires2fa@example.com", password="secret-password")

    assert payload["status"] == "challenge_required"
    challenge = store.challenges[payload["challenge_id"]]
    assert challenge["account_id"] == "requires2fa@example.com"
    assert "password" not in challenge


@pytest.mark.asyncio
async def test_security_code_requires_password() -> None:
    claims_by_token: dict[str, dict[str, Any]] = {}
    store = _RecordingSessionStore()
    signer = _FakeTokenSigner(claims_by_token)
    service = AuthApiService(
        token_signer=signer,
        session_query=store,
        session_command=store,
        auth_service_factory=lambda username, password: _SecurityCodeRequiredAuthService(),  # noqa: ARG005
    )
    store.put_challenge(
        challenge_id="challenge-id",
        payload={"account_id": "requires2fa@example.com", "flow_id": "flow-1"},
        ttl_seconds=120,
    )

    with pytest.raises(InvalidCredentials, match="Password is required"):
        await service.security_code(challenge_id="challenge-id", code="123456", password="")


def _challenge_service(store: _RecordingSessionStore) -> AuthApiService:
    claims_by_token: dict[str, dict[str, Any]] = {}
    signer = _FakeTokenSigner(claims_by_token)

    def _factory(username: str, password: str):  # noqa: ARG001
        if username == "requires2fa@example.com":
            return _TwoFactorAuthService()
        return _SuccessAuthService()

    return AuthApiService(
        token_signer=signer,
        session_query=store,
        session_command=store,
        auth_service_factory=_factory,
    )


@pytest.mark.asyncio
async def test_unified_challenge_password_step_authenticates() -> None:
    store = _RecordingSessionStore()
    service = _challenge_service(store)

    started = await service.challenge(username="success@example.com")
    challenge_id = str(started["challenge_id"])
    session_id = str(started["session_id"])
    assert started["challenge_type"] == "password_required"

    completed = await service.challenge(
        challenge_id=challenge_id,
        session_id=session_id,
        password_envelope="secret",
    )
    assert completed["challenge_type"] == "authenticated"
    assert completed["access_token"]


@pytest.mark.asyncio
async def test_unified_challenge_rejects_username_and_session_mismatch() -> None:
    store = _RecordingSessionStore()
    service = _challenge_service(store)

    started = await service.challenge(username="success@example.com")
    challenge_id = str(started["challenge_id"])

    with pytest.raises(InvalidChallengeTransition, match="username does not match"):
        await service.challenge(
            challenge_id=challenge_id,
            username="other@example.com",
            password_envelope="secret",
        )

    with pytest.raises(InvalidChallengeTransition, match="session_id does not match"):
        await service.challenge(
            challenge_id=challenge_id,
            session_id="mismatch",
            password_envelope="secret",
        )


@pytest.mark.asyncio
async def test_unified_challenge_operation_resume_flow_propagates_operation_id() -> None:
    store = _RecordingSessionStore()
    service = _challenge_service(store)
    challenge = service.issue_operation_challenge(
        account_id="success@example.com",
        upstream_status=450,
        operation="GET /v1/devices",
        reason="expired",
        operation_id="operation-1",
    )

    pending = await service.challenge(challenge_id=str(challenge["challenge_id"]))
    assert pending["challenge_type"] == "operation_resume_required"
    assert pending["operation_id"] == "operation-1"

    completed = await service.challenge(
        challenge_id=str(challenge["challenge_id"]),
        session_id=str(pending["session_id"]),
        password_envelope="secret",
    )
    assert completed["challenge_type"] == "authenticated"
    assert completed["operation_id"] == "operation-1"


@pytest.mark.asyncio
async def test_unified_challenge_security_code_transition() -> None:
    store = _RecordingSessionStore()
    service = _challenge_service(store)
    challenge = await service.challenge(
        username="requires2fa@example.com",
        password_envelope="secret",
    )
    assert challenge["challenge_type"] == "security_code_required"

    with pytest.raises(InvalidChallengeTransition, match="security_code is required"):
        await service.challenge(
            challenge_id=str(challenge["challenge_id"]),
            session_id=str(challenge["session_id"]),
            password_envelope="secret",
        )

    completed = await service.challenge(
        challenge_id=str(challenge["challenge_id"]),
        session_id=str(challenge["session_id"]),
        password_envelope="secret",
        security_code="123456",
    )
    assert completed["challenge_type"] == "authenticated"
