"""Typed composition settings for API and CLI entrypoints."""

from __future__ import annotations

import json
import os
from typing import Literal, cast

from pydantic import BaseModel, Field

AuthScenario = Literal[
    "success",
    "requires_2fa",
    "invalid_credentials",
    "invalid_security_code",
    "expired_session",
]

_VALID_AUTH_SCENARIOS: set[str] = {
    "success",
    "requires_2fa",
    "invalid_credentials",
    "invalid_security_code",
    "expired_session",
}


def _runtime_env() -> str:
    return os.getenv("PYICLOUD_API_ENV", os.getenv("PYICLOUD_ENV", "dev")).strip().lower()


def _is_non_dev_runtime(runtime_env: str) -> bool:
    return runtime_env not in {"dev", "development", "local", "test", "testing"}


def _parse_auth_scenario_overrides(raw: str) -> dict[str, AuthScenario]:
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as err:
        raise RuntimeError("PYICLOUD_API_AUTH_SCENARIO_OVERRIDES must be valid JSON object") from err
    if not isinstance(payload, dict):
        raise RuntimeError("PYICLOUD_API_AUTH_SCENARIO_OVERRIDES must be a JSON object")

    overrides: dict[str, AuthScenario] = {}
    for raw_username, raw_scenario in payload.items():
        username = str(raw_username).strip().lower()
        scenario = str(raw_scenario).strip().lower()
        if not username:
            raise RuntimeError("PYICLOUD_API_AUTH_SCENARIO_OVERRIDES contains an empty username key")
        if scenario not in _VALID_AUTH_SCENARIOS:
            raise RuntimeError(f"Unsupported auth scenario override: {raw_scenario}")
        overrides[username] = cast(AuthScenario, scenario)
    return overrides


def _normalize_auth_default(raw_default: str) -> AuthScenario:
    value = raw_default.strip().lower()
    if value not in _VALID_AUTH_SCENARIOS:
        raise RuntimeError(f"Unsupported PYICLOUD_API_AUTH_DEFAULT_SCENARIO value: {raw_default}")
    return cast(AuthScenario, value)


def _normalize_session_backend(raw_backend: str) -> Literal["memory", "file"]:
    backend = raw_backend.strip().lower()
    if backend in {"memory", "in-memory", "inmemory"}:
        return "memory"
    if backend == "file":
        return "file"
    raise RuntimeError(f"Unsupported auth session backend: {backend}")


class ApiRuntimeSettings(BaseModel):
    """Runtime environment classification for API composition."""

    runtime_env: str = "dev"

    @property
    def is_non_dev(self) -> bool:
        return _is_non_dev_runtime(self.runtime_env)

    @classmethod
    def from_env(cls) -> ApiRuntimeSettings:
        return cls(runtime_env=_runtime_env())


class ApiAuthSettings(BaseModel):
    """Auth API composition settings parsed from environment variables."""

    jwt_secret: str = "pyicloud-api-dev-secret"
    jwt_secret_explicit: bool = False
    jwt_leeway_seconds: int = 0
    session_backend: Literal["memory", "file"] = "memory"
    session_store_dir: str | None = None
    auth_backend: Literal["scenario"] = "scenario"
    default_scenario: AuthScenario = "success"
    scenario_overrides: dict[str, AuthScenario] = Field(default_factory=dict)
    payload_store_dir: str | None = None

    @classmethod
    def from_env(cls) -> ApiAuthSettings:
        leeway_seconds_raw = os.getenv("PYICLOUD_API_JWT_LEEWAY_SECONDS", "0")
        try:
            leeway_seconds = int(leeway_seconds_raw)
        except ValueError as err:
            raise RuntimeError("PYICLOUD_API_JWT_LEEWAY_SECONDS must be an integer") from err

        session_backend = _normalize_session_backend(os.getenv("PYICLOUD_API_SESSION_BACKEND", "memory"))
        auth_backend = os.getenv("PYICLOUD_API_AUTH_BACKEND", "scenario").strip().lower()
        if auth_backend not in {"scenario", "fake", "deterministic"}:
            raise RuntimeError(f"Unsupported PYICLOUD_API_AUTH_BACKEND value: {auth_backend}")

        default_scenario = _normalize_auth_default(os.getenv("PYICLOUD_API_AUTH_DEFAULT_SCENARIO", "success"))
        scenario_overrides = _parse_auth_scenario_overrides(os.getenv("PYICLOUD_API_AUTH_SCENARIO_OVERRIDES", ""))

        return cls(
            jwt_secret=os.getenv("PYICLOUD_API_JWT_SECRET", "pyicloud-api-dev-secret"),
            jwt_secret_explicit="PYICLOUD_API_JWT_SECRET" in os.environ,
            jwt_leeway_seconds=leeway_seconds,
            session_backend=session_backend,
            session_store_dir=os.getenv("PYICLOUD_API_SESSION_STORE_DIR"),
            auth_backend="scenario",
            default_scenario=default_scenario,
            scenario_overrides=scenario_overrides,
            payload_store_dir=os.getenv("PYICLOUD_SESSION_STORE_DIR"),
        )


class AccessControlSettings(BaseModel):
    """Access-control service composition settings."""

    backend: Literal["memory", "file"] = "memory"
    store_dir: str | None = None
    bootstrap_admin: str | None = None

    @classmethod
    def from_env(cls, *, is_non_dev: bool) -> AccessControlSettings:
        backend_default = "file" if is_non_dev else "memory"
        backend_name = os.getenv("PYICLOUD_API_ACL_BACKEND", backend_default).strip().lower()
        if backend_name in {"memory", "in-memory", "inmemory"}:
            if is_non_dev:
                raise RuntimeError("PYICLOUD_API_ACL_BACKEND must use file storage in non-dev runtime")
            backend = "memory"
        elif backend_name == "file":
            backend = "file"
        else:
            raise RuntimeError(f"Unsupported access-control backend: {backend_name}")
        return cls(
            backend=backend,
            store_dir=os.getenv("PYICLOUD_API_ACL_STORE_DIR"),
            bootstrap_admin=os.getenv("PYICLOUD_API_BOOTSTRAP_ADMIN"),
        )


class OperationSuspensionSettings(BaseModel):
    """Suspended-operation service composition settings."""

    backend: Literal["memory", "file"] = "memory"
    store_dir: str | None = None
    ttl_seconds: int = 300
    max_pending_per_user: int = 25
    max_pending_global: int = 500
    max_payload_bytes: int = 65536

    @classmethod
    def from_env(cls, *, is_non_dev: bool) -> OperationSuspensionSettings:
        backend_default = "file" if is_non_dev else "memory"
        backend_name = os.getenv("PYICLOUD_API_OPERATION_BACKEND", backend_default).strip().lower()
        if backend_name in {"memory", "in-memory", "inmemory"}:
            if is_non_dev:
                raise RuntimeError("PYICLOUD_API_OPERATION_BACKEND must use file storage in non-dev runtime")
            backend = "memory"
        elif backend_name == "file":
            backend = "file"
        else:
            raise RuntimeError(f"Unsupported operation-suspension backend: {backend_name}")

        ttl_raw = os.getenv("PYICLOUD_API_OPERATION_TTL_SECONDS", "300")
        max_user_raw = os.getenv("PYICLOUD_API_OPERATION_MAX_PENDING_PER_USER", "25")
        max_global_raw = os.getenv("PYICLOUD_API_OPERATION_MAX_PENDING_GLOBAL", "500")
        max_payload_raw = os.getenv("PYICLOUD_API_OPERATION_MAX_PAYLOAD_BYTES", "65536")
        try:
            ttl_seconds = int(ttl_raw)
            max_pending_per_user = int(max_user_raw)
            max_pending_global = int(max_global_raw)
            max_payload_bytes = int(max_payload_raw)
        except ValueError as err:
            raise RuntimeError("Operation suspension configuration values must be integers") from err

        return cls(
            backend=backend,
            store_dir=os.getenv("PYICLOUD_API_OPERATION_STORE_DIR"),
            ttl_seconds=ttl_seconds,
            max_pending_per_user=max_pending_per_user,
            max_pending_global=max_pending_global,
            max_payload_bytes=max_payload_bytes,
        )


class AuthAbuseGuardSettings(BaseModel):
    """Auth abuse-guard composition settings."""

    window_seconds: int = 300
    lockout_seconds: int = 300
    max_attempts_per_account: int = 30
    max_attempts_per_ip: int = 60
    max_attempts_per_session: int = 12

    @classmethod
    def from_env(cls) -> AuthAbuseGuardSettings:
        window_raw = os.getenv("PYICLOUD_API_AUTH_RATE_WINDOW_SECONDS", "300")
        lockout_raw = os.getenv("PYICLOUD_API_AUTH_LOCKOUT_SECONDS", "300")
        per_account_raw = os.getenv("PYICLOUD_API_AUTH_MAX_ATTEMPTS_PER_ACCOUNT", "30")
        per_ip_raw = os.getenv("PYICLOUD_API_AUTH_MAX_ATTEMPTS_PER_IP", "60")
        per_session_raw = os.getenv("PYICLOUD_API_AUTH_MAX_ATTEMPTS_PER_SESSION", "12")
        try:
            return cls(
                window_seconds=int(window_raw),
                lockout_seconds=int(lockout_raw),
                max_attempts_per_account=int(per_account_raw),
                max_attempts_per_ip=int(per_ip_raw),
                max_attempts_per_session=int(per_session_raw),
            )
        except ValueError as err:
            raise RuntimeError("Auth abuse guard configuration values must be integers") from err


class ObservabilitySettings(BaseModel):
    """Observability query adapter composition settings."""

    adapter: Literal["null", "otel"] = "null"
    timeout_seconds: float = 10.0
    promql_endpoint: str | None = None
    traceql_endpoint: str | None = None
    logql_endpoint: str | None = None

    @classmethod
    def from_env(cls) -> ObservabilitySettings:
        adapter_name = os.getenv("PYICLOUD_OBSERVABILITY_ADAPTER", "null").strip().lower()
        if adapter_name not in {"null", "otel"}:
            raise RuntimeError(f"Unsupported observability adapter: {adapter_name}")

        timeout_seconds = 10.0
        if adapter_name == "otel":
            timeout_raw = os.getenv("PYICLOUD_OBSERVABILITY_TIMEOUT_SECONDS", "10.0")
            try:
                timeout_seconds = float(timeout_raw)
            except ValueError as err:
                raise RuntimeError("PYICLOUD_OBSERVABILITY_TIMEOUT_SECONDS must be numeric") from err

        return cls(
            adapter=cast(Literal["null", "otel"], adapter_name),
            timeout_seconds=timeout_seconds,
            promql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_PROMQL_ENDPOINT"),
            traceql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_TRACEQL_ENDPOINT"),
            logql_endpoint=os.getenv("PYICLOUD_OBSERVABILITY_LOGQL_ENDPOINT"),
        )


class ApiCompositionSettings(BaseModel):
    """Top-level API composition settings grouped by subsystem."""

    runtime: ApiRuntimeSettings
    auth: ApiAuthSettings
    access_control: AccessControlSettings
    operation_suspension: OperationSuspensionSettings
    auth_abuse_guard: AuthAbuseGuardSettings
    observability: ObservabilitySettings

    @classmethod
    def from_env(cls) -> ApiCompositionSettings:
        runtime = ApiRuntimeSettings.from_env()
        auth = ApiAuthSettings.from_env()
        if runtime.is_non_dev and not auth.jwt_secret_explicit:
            raise RuntimeError("PYICLOUD_API_JWT_SECRET must be explicitly configured in non-dev runtime")
        return cls(
            runtime=runtime,
            auth=auth,
            access_control=AccessControlSettings.from_env(is_non_dev=runtime.is_non_dev),
            operation_suspension=OperationSuspensionSettings.from_env(is_non_dev=runtime.is_non_dev),
            auth_abuse_guard=AuthAbuseGuardSettings.from_env(),
            observability=ObservabilitySettings.from_env(),
        )


__all__ = [
    "AccessControlSettings",
    "ApiAuthSettings",
    "ApiCompositionSettings",
    "ApiRuntimeSettings",
    "AuthAbuseGuardSettings",
    "AuthScenario",
    "ObservabilitySettings",
    "OperationSuspensionSettings",
]
