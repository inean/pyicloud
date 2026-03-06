"""Application service that powers API authentication endpoints."""

from __future__ import annotations

from collections.abc import Callable
from time import time
from typing import Any
from uuid import uuid4

from pyicloud.domain import (
    AuthPrincipal,
    ChallengeExpired,
    InvalidCredentials,
    InvalidSecurityCode,
    SecurityCodeRequired,
    Unauthorized,
)
from pyicloud.domain.auth_flow import AuthFlowRequest
from pyicloud.ports import SessionCommandPort, SessionQueryPort, TokenSignerPort

AuthServiceFactory = Callable[[str, str], Any]


class AuthApiService:
    """Coordinate login, 2FA completion, token minting, and logout for API clients."""

    def __init__(
        self,
        *,
        token_signer: TokenSignerPort,
        session_query: SessionQueryPort,
        session_command: SessionCommandPort,
        auth_service_factory: AuthServiceFactory,
        token_ttl_seconds: int = 3600,
        challenge_ttl_seconds: int = 300,
    ):
        self._token_signer = token_signer
        self._session_query = session_query
        self._session_command = session_command
        self._token_ttl_seconds = token_ttl_seconds
        self._challenge_ttl_seconds = challenge_ttl_seconds
        self._auth_service_factory = auth_service_factory

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

    def _issue_challenge(
        self,
        *,
        account_id: str,
        challenge_type: str,
        next_step: str,
        flow_id: str | None = None,
        retryable: bool = True,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        challenge_id = str(uuid4())
        flow = flow_id or str(uuid4())
        expires_at = int(time()) + self._challenge_ttl_seconds
        challenge_payload = {
            "account_id": account_id,
            "challenge_type": challenge_type,
            "flow_id": flow,
            "next_step": next_step,
            "retryable": retryable,
        }
        if payload:
            challenge_payload.update(payload)
        self._session_command.put_challenge(
            challenge_id=challenge_id,
            payload=challenge_payload,
            ttl_seconds=self._challenge_ttl_seconds,
        )
        return {
            "challenge_id": challenge_id,
            "challenge_ttl": self._challenge_ttl_seconds,
            "challenge_type": challenge_type,
            "account_id": account_id,
            "flow_id": flow,
            "expires_at": expires_at,
            "next_step": next_step,
            "retryable": retryable,
        }

    def issue_operation_challenge(
        self,
        *,
        account_id: str,
        upstream_status: int | None,
        operation: str,
        reason: str,
    ) -> dict[str, Any]:
        challenge = self._issue_challenge(
            account_id=account_id,
            challenge_type="session_refresh",
            next_step="auth.login",
            retryable=True,
            payload={
                "upstream_status": upstream_status,
                "operation": operation,
                "reason": reason,
            },
        )
        challenge["upstream_status"] = upstream_status
        challenge["operation"] = operation
        return challenge

    @staticmethod
    def _revocation_key(*, username: str, token_id: str) -> str:
        return f"{username}:{token_id}"

    async def login(self, *, username: str, password: str, flow_id: str | None = None) -> dict[str, Any]:
        auth_service = self._auth_service_factory(username, password)
        flow_id = (flow_id or "").strip() or str(uuid4())
        request = AuthFlowRequest(
            refresh_signin=True,
            security_code=None,
            require_trust_token=True,
            flow_id=flow_id,
        )
        try:
            await auth_service.run(account_id=username, request=request)
        except SecurityCodeRequired:
            challenge = self._issue_challenge(
                account_id=username,
                challenge_type="security_code",
                next_step="auth.security_code",
                flow_id=flow_id,
            )
            return {
                "status": "challenge_required",
                **challenge,
            }
        except RuntimeError as err:
            raise InvalidCredentials(str(err) or "Invalid credentials") from err

        token_data = self._issue_token(username=username)
        return {
            "status": "authenticated",
            "flow_id": flow_id,
            **token_data,
        }

    async def security_code(
        self,
        *,
        challenge_id: str,
        code: str,
        password: str,
        username: str | None = None,
    ) -> dict[str, Any]:
        challenge = self._session_query.get_challenge(challenge_id)
        if challenge is None:
            raise ChallengeExpired("Challenge is missing or expired")

        challenge_username = str(challenge.get("account_id") or challenge.get("username") or "").strip()
        username = (username or challenge_username).strip()
        if not username:
            raise InvalidCredentials("Challenge is missing account context")
        if not password:
            raise InvalidCredentials("Password is required to complete challenge")
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
