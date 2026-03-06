"""Application service that powers API authentication endpoints."""

from __future__ import annotations

from collections.abc import Callable
from time import time
from typing import Any
from uuid import uuid4

from pyicloud.domain import (
    AccessControlEntry,
    AuthPrincipal,
    ChallengeExpired,
    Forbidden,
    InvalidChallengeTransition,
    InvalidCredentials,
    InvalidSecurityCode,
    SecurityCodeRequired,
    Unauthorized,
)
from pyicloud.domain.auth_flow import AuthFlowRequest
from pyicloud.ports import AccessControlQueryPort, SessionCommandPort, SessionQueryPort, TokenSignerPort

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
        access_query: AccessControlQueryPort | None = None,
        enforce_allowlist: bool = False,
        token_ttl_seconds: int = 3600,
        challenge_ttl_seconds: int = 300,
    ):
        self._token_signer = token_signer
        self._session_query = session_query
        self._session_command = session_command
        self._token_ttl_seconds = token_ttl_seconds
        self._challenge_ttl_seconds = challenge_ttl_seconds
        self._auth_service_factory = auth_service_factory
        self._access_query = access_query
        self._enforce_allowlist = enforce_allowlist

    def _issue_token(self, *, username: str, role: str, acl_version: int) -> dict[str, Any]:
        token_id = str(uuid4())
        token = self._token_signer.sign(
            subject=username,
            claims={
                "jti": token_id,
                "scope": "pyicloud.api",
                "role": role,
                "acl_version": acl_version,
            },
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

    def _allowlist_entry(self, *, username: str) -> AccessControlEntry | None:
        if self._access_query is None:
            return None
        return self._access_query.get_entry(username)

    def _authorize_login_username(self, *, username: str) -> AccessControlEntry | None:
        entry = self._allowlist_entry(username=username)
        if entry is None:
            if self._enforce_allowlist:
                raise Forbidden("Account is not allowlisted for this backend")
            return None
        if entry.status != "active":
            raise Forbidden("Account is disabled")
        return entry

    def _token_acl_context(self, *, username: str) -> tuple[str, int]:
        entry = self._allowlist_entry(username=username)
        if entry is None:
            if self._enforce_allowlist:
                raise Forbidden("Account is not allowlisted for this backend")
            return ("member", 0)
        if entry.status != "active":
            raise Forbidden("Account is disabled")
        return (entry.role, entry.acl_version)

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
            "expires_at": expires_at,
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

    @staticmethod
    def _challenge_identity(
        *,
        username: str | None,
        challenge: dict[str, Any] | None = None,
    ) -> str:
        candidate = str(username or "").strip()
        if candidate:
            return candidate
        if challenge is None:
            return ""
        return str(challenge.get("account_id") or challenge.get("username") or "").strip()

    @staticmethod
    def _challenge_expires_at(challenge: dict[str, Any], *, fallback_ttl_seconds: int) -> int:
        raw_expires = challenge.get("expires_at")
        try:
            expires_at = int(str(raw_expires))
        except (TypeError, ValueError):
            expires_at = int(time()) + fallback_ttl_seconds
        return expires_at

    def _to_password_required_response(self, *, challenge: dict[str, Any]) -> dict[str, Any]:
        return {
            "challenge_type": "password_required",
            "challenge_id": str(challenge.get("challenge_id", "")) or None,
            "session_id": str(challenge.get("flow_id", "")) or None,
            "expires_at": int(challenge.get("expires_at", int(time()) + self._challenge_ttl_seconds)),
            "retryable": bool(challenge.get("retryable", True)),
            "next_step": "password_envelope",
            "account_id": str(challenge.get("account_id", "")) or None,
        }

    def _to_login_challenge_response(self, *, login_result: dict[str, Any]) -> dict[str, Any]:
        status = str(login_result.get("status", "")).strip()
        if status == "authenticated":
            return {
                "challenge_type": "authenticated",
                "challenge_id": None,
                "session_id": str(login_result.get("flow_id", "")) or None,
                "expires_at": int(login_result.get("expires_at", 0)),
                "retryable": False,
                "next_step": None,
                "access_token": login_result.get("access_token"),
                "token_type": login_result.get("token_type"),
                "expires_in": login_result.get("expires_in"),
                "account_id": None,
            }
        if status == "challenge_required" and str(login_result.get("challenge_type", "")) == "security_code":
            return {
                "challenge_type": "security_code_required",
                "challenge_id": str(login_result.get("challenge_id", "")) or None,
                "session_id": str(login_result.get("flow_id", "")) or None,
                "expires_at": int(login_result.get("expires_at", int(time()) + self._challenge_ttl_seconds)),
                "retryable": bool(login_result.get("retryable", True)),
                "next_step": "security_code",
                "account_id": str(login_result.get("account_id", "")) or None,
            }
        raise InvalidChallengeTransition("Unexpected auth state transition")

    def _to_operation_resume_response(self, *, challenge_id: str, challenge: dict[str, Any]) -> dict[str, Any]:
        return {
            "challenge_type": "operation_resume_required",
            "challenge_id": challenge_id,
            "session_id": str(challenge.get("flow_id", "")) or None,
            "expires_at": self._challenge_expires_at(challenge, fallback_ttl_seconds=self._challenge_ttl_seconds),
            "retryable": bool(challenge.get("retryable", True)),
            "next_step": "password_envelope",
            "account_id": self._challenge_identity(username=None, challenge=challenge) or None,
            "operation": str(challenge.get("operation", "")) or None,
            "operation_id": str(challenge.get("operation_id", "")) or None,
        }

    async def challenge(
        self,
        *,
        username: str | None = None,
        challenge_id: str | None = None,
        password_envelope: str | None = None,
        security_code: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        normalized_username = str(username or "").strip()
        normalized_challenge_id = str(challenge_id or "").strip()
        normalized_session_id = str(session_id or "").strip()
        normalized_password = str(password_envelope or "")
        normalized_security_code = str(security_code or "").strip()

        if not normalized_challenge_id:
            if not normalized_username:
                raise InvalidChallengeTransition("username is required when challenge_id is not provided")
            if normalized_security_code:
                raise InvalidChallengeTransition("security_code requires challenge_id")
            if not normalized_password:
                self._authorize_login_username(username=normalized_username)
                challenge = self._issue_challenge(
                    account_id=normalized_username,
                    challenge_type="password_required",
                    next_step="auth.challenge.password",
                    flow_id=normalized_session_id or None,
                )
                return self._to_password_required_response(challenge=challenge)
            login_result = await self.login(
                username=normalized_username,
                password=normalized_password,
                flow_id=normalized_session_id or None,
            )
            return self._to_login_challenge_response(login_result=login_result)

        challenge_payload = self._session_query.get_challenge(normalized_challenge_id)
        if challenge_payload is None:
            raise ChallengeExpired("Challenge is missing or expired")
        challenge_type = str(challenge_payload.get("challenge_type", "")).strip().lower()
        challenge_username = self._challenge_identity(username=None, challenge=challenge_payload)
        resolved_username = challenge_username or normalized_username
        resolved_flow_id = str(challenge_payload.get("flow_id", "")).strip() or None
        if normalized_username and challenge_username and normalized_username != challenge_username:
            raise InvalidChallengeTransition("username does not match challenge context")
        if normalized_session_id and resolved_flow_id and normalized_session_id != resolved_flow_id:
            raise InvalidChallengeTransition("session_id does not match challenge context")

        if challenge_type == "password_required":
            if normalized_security_code:
                raise InvalidChallengeTransition("security_code is not valid for password_required challenge")
            if not normalized_password:
                return self._to_password_required_response(
                    challenge={"challenge_id": normalized_challenge_id, **challenge_payload}
                )
            if not resolved_username:
                raise InvalidChallengeTransition("password_required challenge is missing account context")
            self._session_command.delete_challenge(normalized_challenge_id)
            login_result = await self.login(
                username=resolved_username,
                password=normalized_password,
                flow_id=resolved_flow_id,
            )
            return self._to_login_challenge_response(login_result=login_result)

        if challenge_type == "security_code":
            if not normalized_password:
                raise InvalidChallengeTransition("password_envelope is required for security_code challenge")
            if not normalized_security_code:
                raise InvalidChallengeTransition("security_code is required for security_code challenge")
            result = await self.security_code(
                challenge_id=normalized_challenge_id,
                code=normalized_security_code,
                password=normalized_password,
                username=resolved_username or None,
            )
            return self._to_login_challenge_response(login_result=result)

        if challenge_type == "session_refresh":
            if normalized_security_code:
                raise InvalidChallengeTransition("security_code is not valid for operation resume challenge")
            if not normalized_password:
                return self._to_operation_resume_response(
                    challenge_id=normalized_challenge_id,
                    challenge=challenge_payload,
                )
            if not resolved_username:
                raise InvalidChallengeTransition("operation resume challenge is missing account context")
            operation_id = str(challenge_payload.get("operation_id", "")).strip() or None
            self._session_command.delete_challenge(normalized_challenge_id)
            login_result = await self.login(
                username=resolved_username,
                password=normalized_password,
                flow_id=resolved_flow_id,
            )
            response = self._to_login_challenge_response(login_result=login_result)
            response["operation_id"] = operation_id
            return response

        raise InvalidChallengeTransition(f"Unsupported challenge type: {challenge_type or 'unknown'}")

    def issue_operation_challenge(
        self,
        *,
        account_id: str,
        upstream_status: int | None,
        operation: str,
        reason: str,
        operation_id: str | None = None,
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
                "operation_id": operation_id,
            },
        )
        challenge["upstream_status"] = upstream_status
        challenge["operation"] = operation
        challenge["operation_id"] = operation_id
        return challenge

    @staticmethod
    def _revocation_key(*, username: str, token_id: str) -> str:
        return f"{username}:{token_id}"

    async def login(self, *, username: str, password: str, flow_id: str | None = None) -> dict[str, Any]:
        self._authorize_login_username(username=username)
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

        role, acl_version = self._token_acl_context(username=username)
        token_data = self._issue_token(username=username, role=role, acl_version=acl_version)
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
        self._authorize_login_username(username=username)
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
        role, acl_version = self._token_acl_context(username=username)
        token_data = self._issue_token(username=username, role=role, acl_version=acl_version)
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
        role = str(claims.get("role", "member")).strip().lower()
        raw_acl_version = claims.get("acl_version", 0)
        try:
            acl_version = int(raw_acl_version)
        except (TypeError, ValueError) as err:
            raise Unauthorized("Token payload is incomplete") from err

        if role not in {"member", "admin"}:
            raise Unauthorized("Token payload is incomplete")
        if acl_version < 0:
            raise Unauthorized("Token payload is incomplete")
        if not username or not token_id or expires_at <= 0:
            raise Unauthorized("Token payload is incomplete")

        token_revocation_key = self._revocation_key(username=username, token_id=token_id)
        if self._session_query.is_token_revoked(token_revocation_key):
            raise Unauthorized("Token has been revoked")
        if self._session_query.is_token_revoked(token_id):
            raise Unauthorized("Token has been revoked")

        if self._access_query is not None:
            entry = self._access_query.get_entry(username)
            if entry is None:
                if self._enforce_allowlist or acl_version > 0:
                    raise Unauthorized("Token ACL context is stale")
            else:
                if entry.status != "active":
                    raise Unauthorized("Token ACL context is stale")
                if acl_version != entry.acl_version or role != entry.role:
                    raise Unauthorized("Token ACL context is stale")
                role = entry.role
                acl_version = entry.acl_version

        return AuthPrincipal(
            username=username,
            token_id=token_id,
            expires_at=expires_at,
            role=role if role in {"member", "admin"} else "member",
            acl_version=acl_version,
        )

    def logout(self, *, token: str) -> None:
        principal = self.session(token=token)
        ttl_seconds = max(1, principal.expires_at - int(time()))
        self._session_command.revoke_token(
            token_id=self._revocation_key(username=principal.username, token_id=principal.token_id),
            ttl_seconds=ttl_seconds,
        )
