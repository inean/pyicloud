"""Domain primitives for auth/session flow orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AuthStep(StrEnum):
    """Auth/session milestones derived from the kkza reference flow."""

    SIGNIN = "signin"
    SECURITY_CODE = "security_code"
    TRUST = "trust"
    ACCOUNT_LOGIN = "account_login"
    VALIDATE = "validate"


class AuthFlowError(Exception):
    """Base domain error for auth flow orchestration."""


class SecurityCodeRequired(AuthFlowError):
    """Raised when signin requires 2FA but no security code is provided."""


@dataclass(frozen=True, slots=True)
class AuthFlowRequest:
    """Input for auth/session flow execution."""

    refresh_signin: bool = True
    security_code: str | None = None
    require_trust_token: bool = True
    flow_id: str | None = None


@dataclass(frozen=True, slots=True)
class AuthFlowResult:
    """Output for auth/session flow execution."""

    steps: tuple[AuthStep, ...]
    session_active: bool
    flow_id: str | None = None
