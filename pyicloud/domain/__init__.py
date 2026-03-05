"""Domain models and errors for the new auth/session core."""

from .api_errors import (
    ApiDomainError,
    BackendUnavailable,
    ChallengeExpired,
    ChallengeRequired,
    InvalidCredentials,
    InvalidSecurityCode,
    QueryExecutionFailed,
    Unauthorized,
    UnsupportedQueryMode,
)
from .api_models import AuthPrincipal
from .auth_flow import AuthFlowError, AuthFlowRequest, AuthFlowResult, AuthStep, SecurityCodeRequired

__all__ = [
    "ApiDomainError",
    "AuthPrincipal",
    "AuthFlowError",
    "AuthFlowRequest",
    "AuthFlowResult",
    "AuthStep",
    "BackendUnavailable",
    "ChallengeExpired",
    "ChallengeRequired",
    "InvalidCredentials",
    "InvalidSecurityCode",
    "QueryExecutionFailed",
    "SecurityCodeRequired",
    "UnsupportedQueryMode",
    "Unauthorized",
]
