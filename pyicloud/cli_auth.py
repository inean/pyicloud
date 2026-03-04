"""CLI-oriented helpers for bootstrap auth/session flow."""

from __future__ import annotations

import getpass
from typing import Any, Callable

from pyicloud.application import AuthSessionService
from pyicloud.bootstrap import build_auth_session_service
from pyicloud.domain import AuthFlowRequest, AuthFlowResult, SecurityCodeRequired
from pyicloud.models.settings import Settings
from pyicloud.trees.setup import SetupHooks


class CliSetupHooks(SetupHooks):
    """CLI implementation of setup hooks for bootstrap auth flow."""

    def __init__(
        self,
        *,
        password: str,
        interactive: bool,
        getpass_fn: Callable[[str], str] = getpass.getpass,
        input_fn: Callable[[str], str] = input,
    ):
        self._password = password
        self._interactive = interactive
        self._getpass = getpass_fn
        self._input = input_fn

    def get_password(self, username: str) -> str:
        if self._password:
            return self._password
        if not self._interactive:
            return ""
        return self._getpass(f"Password for {username}: ")

    def get_security_code(self, device: Any = None) -> str:
        if not self._interactive:
            return ""
        return self._input("(string) --> ")

    def get_trusted_device(self, devices):
        return None


async def run_bootstrap_auth(
    *,
    username: str,
    password: str,
    interactive: bool,
    security_code: str | None = None,
    store_dir: str | None = None,
    settings_factory: Callable[[str, str | None], Settings] = Settings.create,
    service_builder: Callable[..., AuthSessionService] = build_auth_session_service,
) -> AuthFlowResult:
    """Authenticate with the new bootstrap service flow for CLI migration."""
    settings = settings_factory(username, password or None)
    hooks = CliSetupHooks(password=password, interactive=interactive)
    service = service_builder(settings=settings, hooks=hooks, store_dir=store_dir)

    request = AuthFlowRequest(refresh_signin=True, security_code=None, require_trust_token=True)
    try:
        return await service.run(account_id=username, request=request)
    except SecurityCodeRequired:
        if not interactive:
            raise
        security_code = security_code or hooks.get_security_code()
        request = AuthFlowRequest(refresh_signin=False, security_code=security_code, require_trust_token=True)
        return await service.run(account_id=username, request=request)
