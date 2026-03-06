"""Application service for kkza-compatible auth/session sequencing."""

from __future__ import annotations

from collections.abc import Mapping

from pyicloud.domain import AuthFlowRequest, AuthFlowResult, AuthStep, SecurityCodeRequired
from pyicloud.log import LOGGER
from pyicloud.platform.telemetry.upstream import bind_upstream_context, inject_flow_into_payload
from pyicloud.ports import AuthSessionPort, SessionStorePort


class AuthSessionService:
    """Orchestrate signin/security/trust/validate flow through outbound ports."""

    def __init__(self, auth: AuthSessionPort, store: SessionStorePort | None = None):
        self._auth = auth
        self._store = store

    def _persist_payload(self, *, account_id: str, payload: Mapping[str, object], flow_id: str) -> None:
        if self._store is None:
            return
        self._store.save(account_id, inject_flow_into_payload(dict(payload), flow_id=flow_id))

    async def _try_validate_fast_path(self, *, refresh_signin: bool) -> Mapping[str, object] | None:
        if refresh_signin:
            return None
        try:
            return dict(await self._auth.session_validate())
        except Exception as err:  # noqa: BLE001 - fast-path fallback is intentionally broad.
            LOGGER.debug("Session validate fast path failed; falling back to full auth flow: %s", err)
            return None

    async def run(self, account_id: str, request: AuthFlowRequest) -> AuthFlowResult:
        """Execute a full auth/session flow aligned with the kkza reference."""
        steps: list[AuthStep] = []

        with bind_upstream_context(
            flow_id=request.flow_id,
            operation="auth.bootstrap",
            username=account_id,
        ) as context:
            if (api_payload := await self._try_validate_fast_path(refresh_signin=request.refresh_signin)) is not None:
                steps.append(AuthStep.VALIDATE)
                flow_id = context["flow_id"]
                self._persist_payload(account_id=account_id, payload=api_payload, flow_id=flow_id)
                return AuthFlowResult(steps=tuple(steps), session_active=True, flow_id=flow_id)

            requires_security_code = await self._auth.signin(refresh_signin=request.refresh_signin)
            steps.append(AuthStep.SIGNIN)

            if requires_security_code:
                if not request.security_code:
                    raise SecurityCodeRequired("Security code is required for this account")
                await self._auth.security_code(request.security_code)
                steps.append(AuthStep.SECURITY_CODE)

                await self._auth.trust()
                steps.append(AuthStep.TRUST)

            await self._auth.account_login(require_trust_token=request.require_trust_token)
            steps.append(AuthStep.ACCOUNT_LOGIN)

            api_payload = await self._auth.session_validate()
            steps.append(AuthStep.VALIDATE)

            flow_id = context["flow_id"]
            self._persist_payload(account_id=account_id, payload=dict(api_payload), flow_id=flow_id)

            return AuthFlowResult(steps=tuple(steps), session_active=True, flow_id=flow_id)
