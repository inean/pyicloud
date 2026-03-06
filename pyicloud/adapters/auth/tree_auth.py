"""Tree-based auth/session adapter implementation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.adapters.tree_runtime import FileBackedTreeRuntimeAdapter
from pyicloud.domain import SecurityCodeRequired
from pyicloud.ports import AuthSessionPort
from pyicloud.sessions._contracts import BaseResponse
from pyicloud.trees.setup import SetupModelTree


class TreeAuthSessionAdapter(AuthSessionPort):
    """Adapter that runs auth/session operations through SetupModelTree."""

    def __init__(self, setup_model: SetupModelTree):
        self._setup = setup_model
        self._ensure_runtime_initialized()

    def _ensure_runtime_initialized(self) -> None:
        has_runtime_port = getattr(self._setup, "has_runtime_port", None)
        set_runtime_port = getattr(self._setup, "set_runtime_port", None)
        ensure_runtime_initialized = getattr(self._setup, "ensure_runtime_initialized", None)

        if not callable(ensure_runtime_initialized):
            return

        injected_fallback_runtime = False
        if callable(has_runtime_port) and callable(set_runtime_port) and not has_runtime_port():
            set_runtime_port(FileBackedTreeRuntimeAdapter())
            injected_fallback_runtime = True

        preserved_password = getattr(self._setup, "password", None) if injected_fallback_runtime else None
        ensure_runtime_initialized()
        if injected_fallback_runtime and preserved_password:
            try:
                self._setup.password = preserved_password
            except Exception:
                # Best-effort compatibility path for loosely typed setup fakes.
                pass

    def close(self) -> None:
        teardown_runtime = getattr(self._setup, "teardown_runtime", None)
        if callable(teardown_runtime):
            teardown_runtime()

    @staticmethod
    def _raise_for_error(response: BaseResponse, fallback: str) -> None:
        if bool(response):
            return
        if response.errors:
            error = response.errors[0]
            message = getattr(error, "message", fallback)
            raise RuntimeError(str(message))
        raise RuntimeError(fallback)

    @staticmethod
    def _coerce_payload(payload: Any) -> Mapping[str, Any]:
        if payload is None:
            return {}
        if isinstance(payload, Mapping):
            return dict(payload)
        if hasattr(payload, "model_dump"):
            data = payload.model_dump(by_alias=True)  # type: ignore[call-arg]
            if isinstance(data, Mapping):
                return dict(data)
        return {}

    async def signin(self, *, refresh_signin: bool) -> bool:
        response = await self._setup.signin(refresh_signin=refresh_signin)
        self._raise_for_error(response, "Sign in failed")
        return bool(await self._setup.is_security_code_required(response=response))

    async def security_code(self, code: str) -> None:
        response = await self._setup.security_code(security_code=code)
        if bool(response):
            return
        if response.errors:
            message = getattr(response.errors[0], "message", "Invalid security code")
            raise SecurityCodeRequired(str(message))
        raise SecurityCodeRequired("Invalid security code")

    async def trust(self) -> None:
        response = await self._setup.trust()
        self._raise_for_error(response, "Trust session failed")

    async def account_login(self, *, require_trust_token: bool) -> None:
        try:
            response = await self._setup.account_login(require_trust_token=require_trust_token)
        except ValueError as err:
            raise SecurityCodeRequired(str(err)) from err
        self._raise_for_error(response, "Account login failed")

    async def session_validate(self) -> Mapping[str, Any]:
        response = await self._setup.session_validate()
        if isinstance(response, BaseResponse):
            self._raise_for_error(response, "Session validation failed")
            return self._coerce_payload(response.body)
        if hasattr(response, "body"):
            if hasattr(response, "errors") and not bool(response):
                fallback = "Session validation failed"
                errors = getattr(response, "errors", [])
                if errors:
                    message = getattr(errors[0], "message", fallback)
                    raise RuntimeError(str(message))
                raise RuntimeError(fallback)
            return self._coerce_payload(getattr(response, "body"))
        return self._coerce_payload(response)
