"""Application service that powers API authentication endpoints."""

from __future__ import annotations

from collections.abc import Callable
from time import time
from typing import Any
from uuid import uuid4

from pyicloud.bootstrap import build_auth_session_service
from pyicloud.domain import (
    AuthPrincipal,
    ChallengeExpired,
    InvalidCredentials,
    InvalidSecurityCode,
    SecurityCodeRequired,
    Unauthorized,
)
from pyicloud.domain.auth_flow import AuthFlowRequest
from pyicloud.models.settings import Settings
from pyicloud.ports import SessionCommandPort, SessionQueryPort, TokenSignerPort
from pyicloud.trees.setup import SetupHooks


class _ApiSetupHooks(SetupHooks):
    """Non-interactive setup hooks used by API authentication flows."""

    def __init__(self, *, password: str):
        self._password = password

    def get_password(self, username: str) -> str:  # noqa: ARG002
        return self._password

    def get_security_code(self, device: Any = None) -> str:  # noqa: ARG002
        return ""

    def get_trusted_device(self, devices):  # noqa: ANN001, ARG002
        return None


AuthServiceFactory = Callable[[str, str], Any]


class AuthApiService:
    """Coordinate login, 2FA completion, token minting, and logout for API clients."""

    def __init__(
        self,
        *,
        token_signer: TokenSignerPort,
        session_query: SessionQueryPort,
        session_command: SessionCommandPort,
        auth_service_factory: AuthServiceFactory | None = None,
        store_dir: str | None = None,
        token_ttl_seconds: int = 3600,
        challenge_ttl_seconds: int = 300,
    ):
        self._token_signer = token_signer
        self._session_query = session_query
        self._session_command = session_command
        self._store_dir = store_dir
        self._token_ttl_seconds = token_ttl_seconds
        self._challenge_ttl_seconds = challenge_ttl_seconds
        self._auth_service_factory = auth_service_factory or self._default_auth_service_factory

    def _default_auth_service_factory(self, username: str, password: str):
        settings = Settings.create(username=username, password=password or None)
        hooks = _ApiSetupHooks(password=password)
        return build_auth_session_service(settings=settings, hooks=hooks, store_dir=self._store_dir)

    def _issue_token(self, *, username: str) -> dict[str, Any]:
        token_id = str(uuid4())
        token = self._token_signer.sign(
            subject=username,
            claims={"jti": token_id, "scope": "pyicloud.api"},
            expires_in_seconds=self._token_ttl_seconds,
        )
        claims = self._token_signer.verify(token)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": self._token_ttl_seconds,
            "token_id": token_id,
            "expires_at": int(claims.get("exp", int(time()) + self._token_ttl_seconds)),
        }

    @staticmethod
    def _revocation_key(*, username: str, token_id: str) -> str:
        return f"{username}:{token_id}"

    async def login(self, *, username: str, password: str) -> dict[str, Any]:
        auth_service = self._auth_service_factory(username, password)
        flow_id = str(uuid4())
        request = AuthFlowRequest(
            refresh_signin=True,
            security_code=None,
            require_trust_token=True,
            flow_id=flow_id,
        )
        try:
            await auth_service.run(account_id=username, request=request)
        except SecurityCodeRequired:
            challenge_id = str(uuid4())
            self._session_command.put_challenge(
                challenge_id=challenge_id,
                payload={"username": username, "password": password, "flow_id": flow_id},
                ttl_seconds=self._challenge_ttl_seconds,
            )
            return {
                "status": "challenge_required",
                "challenge_id": challenge_id,
                "challenge_ttl": self._challenge_ttl_seconds,
                "flow_id": flow_id,
            }
        except RuntimeError as err:
            raise InvalidCredentials(str(err) or "Invalid credentials") from err

        token_data = self._issue_token(username=username)
        return {
            "status": "authenticated",
            "flow_id": flow_id,
            **token_data,
        }

    async def security_code(self, *, challenge_id: str, code: str) -> dict[str, Any]:
        challenge = self._session_query.get_challenge(challenge_id)
        if challenge is None:
            raise ChallengeExpired("Challenge is missing or expired")

        username = str(challenge.get("username", ""))
        password = str(challenge.get("password", ""))
        flow_id = str(challenge.get("flow_id", "")).strip() or str(uuid4())
        auth_service = self._auth_service_factory(username, password)

        request = AuthFlowRequest(
            refresh_signin=False,
            security_code=code,
            require_trust_token=True,
            flow_id=flow_id,
        )
        try:
            await auth_service.run(account_id=username, request=request)
        except SecurityCodeRequired as err:
            raise InvalidSecurityCode(str(err) or "Invalid security code") from err
        except RuntimeError as err:
            raise InvalidCredentials(str(err) or "Invalid credentials") from err

        self._session_command.delete_challenge(challenge_id)
        token_data = self._issue_token(username=username)
        return {
            "status": "authenticated",
            "flow_id": flow_id,
            **token_data,
        }

    def session(self, *, token: str) -> AuthPrincipal:
        try:
            claims = self._token_signer.verify(token)
        except RuntimeError as err:
            raise Unauthorized("Invalid bearer token") from err

        username = str(claims.get("sub", ""))
        token_id = str(claims.get("jti", ""))
        expires_at = int(claims.get("exp", 0))

        if not username or not token_id or expires_at <= 0:
            raise Unauthorized("Token payload is incomplete")

        token_revocation_key = self._revocation_key(username=username, token_id=token_id)
        if self._session_query.is_token_revoked(token_revocation_key):
            raise Unauthorized("Token has been revoked")
        if self._session_query.is_token_revoked(token_id):
            raise Unauthorized("Token has been revoked")

        return AuthPrincipal(username=username, token_id=token_id, expires_at=expires_at)

    def logout(self, *, token: str) -> None:
        principal = self.session(token=token)
        ttl_seconds = max(1, principal.expires_at - int(time()))
        self._session_command.revoke_token(
            token_id=self._revocation_key(username=principal.username, token_id=principal.token_id),
            ttl_seconds=ttl_seconds,
        )
