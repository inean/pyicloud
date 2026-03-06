"""Application service for kkza-compatible auth/session sequencing."""

from __future__ import annotations

from pyicloud.domain import AuthFlowRequest, AuthFlowResult, AuthStep, SecurityCodeRequired
from pyicloud.ports import AuthSessionPort, SessionStorePort
from pyicloud.upstream import bind_upstream_context, inject_flow_into_payload


class AuthSessionService:
    """Orchestrate signin/security/trust/validate flow through outbound ports."""

    def __init__(self, auth: AuthSessionPort, store: SessionStorePort | None = None):
        self._auth = auth
        self._store = store

    async def run(self, account_id: str, request: AuthFlowRequest) -> AuthFlowResult:
        """Execute a full auth/session flow aligned with the kkza reference."""
        steps: list[AuthStep] = []

        with bind_upstream_context(
            flow_id=request.flow_id,
            operation="auth.bootstrap",
            username=account_id,
        ) as context:
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
            if self._store is not None:
                self._store.save(account_id, inject_flow_into_payload(dict(api_payload), flow_id=flow_id))

            return AuthFlowResult(steps=tuple(steps), session_active=True, flow_id=flow_id)
