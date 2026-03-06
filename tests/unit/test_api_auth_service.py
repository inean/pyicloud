from __future__ import annotations

from time import time
from typing import Any

import pytest

from pyicloud.application.api_auth import AuthApiService
from pyicloud.domain import InvalidCredentials, SecurityCodeRequired, Unauthorized


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
